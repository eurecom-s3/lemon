#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <aio.h>

#include "lemon.h"

extern int dump(const struct options *restrict opts, const struct ram_regions *restrict ram_regions, int (*write_f)(void *restrict, void *restrict, const unsigned long), void *restrict args);
extern int check_capability(const cap_value_t cap);

/* Arguments passed to write_on_disk() */
struct disk_args {
    bool async;
    int fd;
    struct aiocb aio_cb;
};

/*
 * write_on_disk() - Writes a memory chunks to the disk file descriptor
 * @args: Pointer to the file descriptor
 * @data: Pointer to the buffer to be written
 * @size: Number of bytes to write
 */
static int write_on_disk(void *restrict args, void *restrict data, const unsigned long size) {
    unsigned long r = 0;
    unsigned long total = 0;
    struct disk_args *disk_args = (struct disk_args *)args;
    struct aiocb *aiocb = &disk_args->aio_cb;

    while(total < size) {
        /* If realtime use async writes */
        if(disk_args->async) {
            (*aiocb).aio_buf = data + total;
            (*aiocb).aio_nbytes = size - total;
            
            if(aio_write(aiocb) < 0) {
                perror("Fail in aio_write");
                return errno;
            }

            /* Steal CPU time while waiting for writing completation */
            while(aio_error(aiocb) == EINPROGRESS) {}

            /* Get total number of written data */
            r = aio_return(aiocb);
            if(r < 0) {
                perror("Fail in aio_write (after write completation)");
                return errno;
            }
        }
        else {
            r = write(disk_args->fd, data + total, size - total);
            if(r == -1) {
                if(errno == EINTR) continue;
                perror("Fail to write on dump file");
                return errno;
            }
        }
        
        total += r;
    }

    return 0;
}

/*
 * dump_on_disk() - Writes a memory dump to a file on disk
 * @opts: Dumping options, including output file path
 * @ram_regions: List of RAM regions to be dumped
 *
 * Opens the specified file for writing, then performs the memory dump using the
 * generic dump function. Ensures data is flushed and file descriptor is closed.
 */
int dump_on_disk(const struct options *restrict opts, const struct ram_regions *restrict ram_regions) {
    
    int fd;
    struct disk_args disk_args;
    int ret = 0;

    /* Check CAP_DAC_OVERRIDE, creation of the file can fail without it */
    if(check_capability(CAP_DAC_OVERRIDE) <= 0) {
        WARN("LEMON does not have CAP_DAC_OVERRIDE, it may fail in dump file creation\n");
    }

    /* Open dump file in write mode */
    fd = open(opts->path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0) {
        perror("Failed to open dump file for writing");
        return errno;
    }

    /* Setup arguments for write_on_disk */
    disk_args.async = opts->realtime;
    disk_args.fd = fd;
    memset(&(disk_args.aio_cb), 0, sizeof(struct aiocb));
    
    /* If in realtime mode, use async write */
    if(opts->realtime) { disk_args.aio_cb.aio_fildes = fd; }

    /* Dump! */
    ret = dump(opts, ram_regions, write_on_disk, (void *)&disk_args);

    if(fd) {
        if(fsync(fd)) { perror("Fail to finalize writes on dump file"); ret = errno; }
        if(close(fd)) { perror("Fail to close dump file"); ret = errno; }
    }

    return ret;
}
