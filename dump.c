#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "lemon.h"

/*
 * dump.c - LiME/raw memory dump: chunked reads, Qualcomm secure pages, progress on stderr.
 */

extern int read_kernel_memory(const uintptr_t addr, const size_t size, const unsigned char **restrict data);
extern int fill_mem_result_buf(const char* pattern, size_t pattern_size, size_t chunk_size, const __u8 **restrict data);
extern uintptr_t phys_to_virt(const struct lemon_ctx *restrict ctx, uintptr_t phy_addr);
extern bool qualcomm_is_secure_page(uintptr_t page_start);

const char fail_pattern[] = "LEMON FAIL READ ";
const char qualcomm_pattern[] = "QUALCOMM SECURE ";

/*
 * dump_region() - Read [region_start, region_end] in granule-sized chunks and write each chunk
 * @region_start: First byte of the region.
 * @region_end: Last byte of the region.
 * @virtual: If false, phys_to_virt() before read_kernel_memory().
 * @granule: Preferred chunk size (PAGE_SIZE after recursive shrink on error).
 * @write_f: Sink for each chunk (disk or socket).
 * @args: Opaque argument for @write_f.
 * @nested: If true, skip progress percentage lines (recursive PAGE_SIZE retry).
 *
 * On read failure with fatal=0: retry once at PAGE_SIZE; then fill fail_pattern in the
 * mmap buffer or pass NULL to the writer for zero-fill. Qualcomm secure pages use
 * qualcomm_pattern when read_data is available.
 *
 * Returns 0 on success, or the first error from read/write paths.
 */
static int dump_region(const struct lemon_ctx *restrict ctx, uintptr_t region_start, const uintptr_t region_end, bool virtual, unsigned int granule, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args, bool nested) {
    const size_t region_size = (region_end - region_start + 1);
    
    int ret = 0;
    size_t chunk_size;
    uintptr_t chunk_start, chunk_end;
    const unsigned char *read_data = NULL;
    int last_printed_pct = -1;  /* Last ten bucket printed (0,10,...,90). */
    chunk_start = region_start;
    uintptr_t virt;

    while (chunk_start <= region_end) {
        /* Read memory region in chunks of maximum granule bytes */
        chunk_end = (region_end - chunk_start + 1 > granule) ? chunk_start + granule - 1 : region_end;
        chunk_size = chunk_end - chunk_start + 1;

        if(ctx->is_qualcomm && qualcomm_is_secure_page(chunk_start))
        {
            DBG("Qualcomm secure page 0x%lx, filling with pattern", chunk_start);
            fill_mem_result_buf(qualcomm_pattern, sizeof(qualcomm_pattern) - 1, chunk_size, &read_data);
        }
        else {
                /* -y: skip read; writer may still allocate zero buffers. */
                if(ctx->opts.simulate) goto bar;

                if(!virtual) {
                    virt = phys_to_virt(ctx, chunk_start);
                    ret = read_kernel_memory(virt, chunk_size, &read_data);
                } else {
                    virt = chunk_start;
                    ret = read_kernel_memory(chunk_start, chunk_size, &read_data);
                }

                if (ret) {
                    DBG("Error reading physical address 0x%lx (0x%lx) size: 0x%zx. Error code: %d", chunk_start, virt, chunk_size, ret);

                    if (ctx->opts.fatal) return ret;

                    /* Retry smaller granule once before substituting fail_pattern / zeros. */
                    if (granule != PAGE_SIZE) {
                        ERR("Try to read it using the minimum page size available");
                        if ((ret = dump_region(ctx, chunk_start, chunk_end, virtual, PAGE_SIZE, write_f, args, true))) return ret;
                        goto next_iter;
                    }

                    fill_mem_result_buf(fail_pattern, sizeof(fail_pattern) - 1, chunk_size, &read_data);
                }
        }
        
        /* Save the chunk */
        if ((ret = write_f(args, read_data, chunk_size))) {
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
 * dump() - For each ctx->ram_regions entry, optional LiME header then dump_region()
 * @ctx: Options (raw, simulate, fatal, granule) and RAM list.
 * @write_f: Per-chunk writer (see dump_on_disk / dump_on_net).
 * @args: Opaque handle for @write_f (fd or net_args).
 *
 * Returns 0 on success, or the first error from header or body writes.
 */
int dump(const struct lemon_ctx *restrict ctx, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args) {
    int ret = 0;
    struct mem_range *range;

    TAILQ_FOREACH(range, &ctx->ram_regions, entries)
    {
        const uintptr_t region_pstart = range->start;
        const uintptr_t region_pend = range->end - 1;

        /* LiME magic + span; skipped for -w raw dumps. */
        if(!ctx->opts.raw) {
            const lime_header header = {
                .magic = 0x4C694D45,
                .version = 1,
                .s_addr = region_pstart,
                .e_addr = region_pend,
                .reserved = {0},
            };

            if ((ret = write_f(args, &header, sizeof(lime_header)))) {
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
