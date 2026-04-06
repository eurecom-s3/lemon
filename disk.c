#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <string.h>
#include <stdlib.h>

#include "lemon.h"

/*
 * disk.c - Write memory dumps to a local file (LiME/raw via dump()).
 */

extern int dump(const struct lemon_ctx *restrict ctx, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args);
extern int check_capability(const struct lemon_ctx *restrict ctx, const cap_value_t cap);

/*
 * write_on_disk() - write(2) loop for dump(); optional zero-fill buffer when data is NULL
 * @args: Pointer to int file descriptor.
 * @data: Source buffer, or NULL to malloc and write zeros (size bytes).
 * @size: Total bytes to write.
 *
 * Returns 0 on success, or errno on first unrecoverable write error.
 */
static int write_on_disk(void *restrict args, const void *restrict data, const unsigned long size) {
    ssize_t r = 0;
    unsigned long total = 0;
    void *dummy_buffer = NULL;
    int ret = 0;

    /* NULL data means the eBPF read was skipped or failed: write zeros instead. */
    if(data == NULL && size > 0) {
        dummy_buffer = malloc(size);
        if(dummy_buffer == NULL) {
            RETURN_ERRNO("Fail to allocate dummy buffer");
        }
        memset(dummy_buffer, 0x00, size);
        data = dummy_buffer;
    }

    while(total < size) {
        r = write(*((int *)args), data + total, size - total);
        if(r == -1) {
            if(errno == EINTR)
                continue;
            ret = errno;
            ERRNO("Fail to write on dump file");
            goto cleanup;
        }
        
        total += r;
    }

    cleanup:
        if(dummy_buffer) free(dummy_buffer);

    return ret;
}

/*
 * dump_on_disk() - open(2) path from ctx->opts.path, run dump(), fsync, close
 * @ctx: Options and RAM regions (see dump()).
 *
 * Preserves the first significant error across fsync/close failures.
 * Returns 0 on success, or errno on failure.
 */
int dump_on_disk(const struct lemon_ctx *restrict ctx) {
    int fd;
    int ret = 0;

    /* Without CAP_DAC_OVERRIDE, open may fail if the directory is not owned by the caller. */
    if(check_capability(ctx, CAP_DAC_OVERRIDE) != 1) {
        WARN("LEMON does not have CAP_DAC_OVERRIDE, it may fail in dump file creation");
    }

    fd = open(ctx->opts.path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0) {
        RETURN_ERRNO("Failed to open dump file for writing");
    }

    ret = dump(ctx, write_on_disk, (void *)&fd);

    if(fsync(fd)) {
        switch (errno) {
            case EINVAL:
                /* fd is bound to a special file (e.g., a pipe, FIFO, or
                 * socket) which does not support synchronization.
                 */
                break;
            default:
                if (!ret) ret = errno;
                ERRNO("Failed to finalize writes on dump file");
        }
    }

    if(close(fd)) {
        if (!ret) ret = errno;
        ERRNO("Failed to close the dump file");
    }

    return ret;
}
