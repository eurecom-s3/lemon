#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "lemon.h"

extern int read_kernel_memory(const uintptr_t addr, const size_t size, unsigned char **restrict data);
extern uintptr_t phys_to_virt(const struct lemon_ctx *restrict ctx, uintptr_t phy_addr);

/*
 * dump_region() - Reads a physical memory region and writes it to a destination in chunks.
 * @region_start: Start of the physical memory region to be dumped.
 * @region_end: End of the physical memory region to be dumped.
 * @granule: Preferred chunk size to use when reading memory.
 * @write_f: Callback function used to write the read memory somewhere (e.g., file, socket).
 * @args: Argument passed to the write function (e.g., file descriptor).
 * @fatal: If true, aborts the dump on any read error; otherwise, tries to recover or zero-fill.
 *
 * This function attempts to read memory between region_start and region_end in chunks
 * defined by `granule`. If a read fails and `fatal` is false, it retries with the smallest
 * allowed granule (system page size). If that also fails, it writes zero-filled data instead.
 */
static int dump_region(const struct lemon_ctx *restrict ctx, uintptr_t region_start, const uintptr_t region_end, unsigned int granule, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args) {
    int ret = 0;
    size_t chunk_size;
    uintptr_t chunk_start, chunk_end;
    unsigned char *read_data = NULL;

    chunk_start = region_start;
    while (chunk_start <= region_end) {
        /* Read memory region in chunks of maximum granule bytes */
        chunk_end = (region_end - chunk_start + 1 > granule) ? chunk_start + granule - 1 : region_end;
        chunk_size = chunk_end - chunk_start + 1;

        if ((ret = read_kernel_memory(phys_to_virt(ctx, chunk_start), chunk_size, &read_data))) {
            ERR("Error reading physical address 0x%lx (0x%lx) size: 0x%zx. Error code: %d", chunk_start, phys_to_virt(ctx, chunk_start), chunk_size, ret);
            
            /* Error reading memory, abort the dump or try with minimum granule of the system */
            if(ctx->opts.fatal) return ret;
            
            if(granule != PAGE_SIZE) {
                ERR("Try to read it using the minimum page size available");
                if((ret = dump_region(ctx, chunk_start, chunk_end, PAGE_SIZE, write_f, args))) return ret;
                goto next_iter;
            }
            
            // TODO REPLACE WITH "ERROR" PATTERN
            else memset(read_data, 0x00, chunk_size); /* We are already at the minimum granule, replace with 0x00 */
        }

        // DBG("Read 0x%lx (0x%lx) Size 0x%lx completed", chunk_start, phys_to_virt(ctx, chunk_start), chunk_size);

        /* Save the chunk */
        if ((ret = write_f(args, read_data, chunk_size)) < 0) {
            ERR("Error saving dump data");
            return ret;
        }

        /* Continue to next chunk */
        next_iter:
            chunk_start = chunk_end + 1;
    }

    return ret;
}

/*
 * dump() - Dumps the contents of system RAM using eBPF-assisted memory reading
 * @opts: Dumping options
 * @ctx->ram_regions: List of RAM regions to be dumped
 * @write_f: Callback function used to write data to the output
 * @args: User-provided context passed to the write callback
 *
 * Iterates through each system RAM region, writes a LiME header, reads the memory region
 * in chunks using eBPF, and writes the contents to the specified output.
 * On read failures, either aborts or fills the chunk with 0xFF, based on fatal mode.
 */
int dump(const struct lemon_ctx *restrict ctx, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args) {
    int ret = 0;

    /* Loop through the system RAM ranges, read the memory ranges and write them on file */
    for (size_t i = 0; i < ctx->ram_regions.num_regions; i++)
    {
        const uintptr_t region_pstart = ctx->ram_regions.regions[i].start;
        const uintptr_t region_pend = ctx->ram_regions.regions[i].end;

        INFO("Dumping Range: 0x%lx-0x%lx", region_pstart, region_pend);

        /* Write the LiMe header for that RAM region to the file (only if not RAW format)*/
        if(!ctx->opts.raw) {
            const lime_header header = {
                .magic = 0x4C694D45,
                .version = 1,
                .s_addr = region_pstart,
                .e_addr = region_pend,
                .reserved = {0},
            };

            if ((ret = write_f(args, &header, sizeof(lime_header))) < 0) {
                ERR("Error saving LiME header");
                return ret;
            }

            DBG("LiME header s_addr: 0x%lx e_addr: 0x%lx", region_pstart, region_pend);
        }

        /* Dump the memory range */
        if((ret = dump_region(ctx, region_pstart, region_pend, ctx->granule, write_f, args))) return ret;
    }

    return ret;
}
