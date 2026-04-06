#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>

#include "lemon.h"

extern int read_kernel_memory(const uintptr_t addr, const size_t size, unsigned char **restrict data);
extern uintptr_t phys_to_virt(const struct lemon_ctx *restrict ctx, uintptr_t phy_addr);
extern bool qualcomm_is_secure_page(uintptr_t page_start);

const char fail_pattern[] = "LEMON FAIL READ ";
const char qualcomm_pattern[] = "QUALCOMM SECURE ";

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
static int dump_region(const struct lemon_ctx *restrict ctx, uintptr_t region_start, const uintptr_t region_end, bool virtual, unsigned int granule, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args, bool nested) {
    int ret = 0;
    size_t chunk_size;
    uintptr_t chunk_start, chunk_end, region_size;
    unsigned char *read_data = NULL;
    int last_printed_pct = -1;                          /* track last printed % */
    region_size = (region_end - region_start + 1);
    chunk_start = region_start;
    uintptr_t virt;

    while (chunk_start <= region_end) {
        /* Read memory region in chunks of maximum granule bytes */
        chunk_end = (region_end - chunk_start + 1 > granule) ? chunk_start + granule - 1 : region_end;
        chunk_size = chunk_end - chunk_start + 1;

        if(ctx->is_qualcomm && qualcomm_is_secure_page(chunk_start))
        {
            DBG("Qualcomm secure page 0x%lx, filling with pattern", chunk_start);
            if(read_data) {
                for (size_t i = 0; i < chunk_size; i += sizeof(qualcomm_pattern) - 1)
                    memcpy(read_data + i, qualcomm_pattern,
                           (i + sizeof(qualcomm_pattern) - 1 <= chunk_size) ? sizeof(qualcomm_pattern) - 1 : chunk_size - i);
            }
        }
        else {
                /* If simulated dump do not read the memory, dump file content undefined */
                if(ctx->opts.simulate) goto bar;

                if(!virtual) {  /* If physical address perform the traduction */
                    virt = phys_to_virt(ctx, chunk_start);
                    ret = read_kernel_memory(virt, chunk_size, &read_data);
                } else {
                    virt = chunk_start;
                    ret = read_kernel_memory(chunk_start, chunk_size, &read_data);
                }

                if (ret) {
                    DBG("Error reading physical address 0x%lx (0x%lx) size: 0x%zx. Error code: %d", chunk_start, virt, chunk_size, ret);
                    
                    if (ctx->opts.fatal) return ret;
                    
                    if (granule != PAGE_SIZE) {
                        ERR("Try to read it using the minimum page size available");
                        if ((ret = dump_region(ctx, chunk_start, chunk_end, virtual, PAGE_SIZE, write_f, args, true))) return ret;
                        goto next_iter;
                    }

                    else if(read_data) {
                        for (size_t i = 0; i < chunk_size; i += sizeof(fail_pattern) - 1)
                            memcpy(read_data + i, fail_pattern,
                                   (i + sizeof(fail_pattern) - 1 <= chunk_size) ? sizeof(fail_pattern) - 1 : chunk_size - i);
                    }
                }
        }
        
        /* Save the chunk */
        if ((ret = write_f(args, read_data, chunk_size)) < 0) {
            ERR("Error saving dump data");
            return ret;
        }
    
        bar:
            if (!nested) {
                int pct = (int)((chunk_start - region_start) * 100 / region_size);
                int pct_bucket = (pct / 10) * 10;           /* round down to 0,10,20,...,90 */

                if (pct_bucket > last_printed_pct) {
                    fprintf(stderr, "\033[2K\r[INFO] Dumping range 0x%lx-0x%lx... [%d%%]",
                            region_start, region_end, pct_bucket);
                    fflush(stderr);
                    last_printed_pct = pct_bucket;
                }
            }

    next_iter:
        chunk_start = chunk_end + 1;
    }

    /* Always print 100% on completion */
    if (!nested) {
        fprintf(stderr, "\033[2K\r[INFO] Dumping range 0x%lx-0x%lx... [100%%]",
                region_start, region_end);
        fflush(stderr);
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
    struct mem_range *range;

    /* Loop through the system RAM ranges, read the memory ranges and write them on file */
    TAILQ_FOREACH(range, &ctx->ram_regions, entries)
    {
        const uintptr_t region_pstart = range->start;
        const uintptr_t region_pend = range->end - 1;

        /* Write the LiMe header for that RAM region to the file (only if not RAW format)*/
        if(!ctx->opts.raw) {
            const lime_header header = {
                .magic = 0x4C694D45,
                .version = 1,
                .s_addr = region_pstart,
                .e_addr = region_pend,
                .reserved = {0},
            };

            if ((ret = write_f(args, &header, sizeof(lime_header))) > 0) {
                ERR("Error saving LiME header");
                return ret;
            }

            DBG("LiME header s_addr: 0x%lx e_addr: 0x%lx", region_pstart, region_pend);
        }

        /* Dump the memory range */
        fprintf(stderr, "\n");
        if((ret = dump_region(ctx, region_pstart, region_pend, range->virtual, ctx->granule, write_f, args, false))) return ret;
    }
    fprintf(stderr, "\n\n");
    return ret;
}
