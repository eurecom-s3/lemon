#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "lemon.h"

extern int read_kernel_memory(const uintptr_t addr, const size_t size, uint8_t **restrict data);

/*
 *  dump_on_disk() - dump memory on disk
 *  @dump_file: filename of the output dump file
 *  @ram_regions: RAM regions addresses extracted from /proc/iomem and converted to virtual addresses 
 * 
 */
int dump_on_disk(const char *const restrict dump_file, const struct ram_regions *const restrict ram_regions) {

    FILE *fp;
    lime_header header;
    size_t written, chunk_size;
    uintptr_t region_start, chunk_start, chunk_end, region_end;
    int ret = 0;
    uint8_t *read_data = NULL;

    /* Open dump file in write mode */
    fp = fopen(dump_file, "w+");
    if(!fp) {
        perror("Failed to open dump file for writing");
        goto cleanup;
    }

    /* Prepare the LiME header */
    header.magic = 0x4C694D45;
    header.version = 1;

    /* Loop through the system RAM ranges, read the memory ranges and write them on file */
    for (size_t i = 0; i < ram_regions->num_regions; i++)
    {
        region_start = ram_regions->regions[i].start;
        region_end = ram_regions->regions[i].end;

        /* Write the LiMe header for that RAM region to the file */
        header.s_addr = region_start;
        header.e_addr = region_end;
        if (fwrite(&header, sizeof(lime_header), 1, fp) != 1) {
            fprintf(stderr, "Error writing LiME header to file\n");
            ret = EIO;
            goto cleanup;
        }

        printf("Dumping Range: 0x%lx-0x%lx\n", region_start, region_end);
        chunk_start = region_start;
        while (chunk_start <= region_end)
        {
            /* Read memory region in chunks of maximum HUGE_PAGE_SIZE bytes */
            chunk_end = (region_end - chunk_start + 1 > HUGE_PAGE_SIZE) ? chunk_start + HUGE_PAGE_SIZE - 1 : region_end;
            chunk_size = chunk_end - chunk_start + 1;
            if ((ret = read_kernel_memory(chunk_start, chunk_size, &read_data))) {
                goto cleanup;
            }

            /* Save the chunk */
            written = fwrite(read_data, 1, chunk_size, fp);
            if (written <= 0)
            {
                fprintf(stderr, "Error writing to dump file\n");
                ret = EIO;
                goto cleanup;
            }

            /* Continue to next chunk */
            chunk_start = chunk_end + 1;
        }
    }

    cleanup:
        if(fp) fclose(fp);

    return ret;
}