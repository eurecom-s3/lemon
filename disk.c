#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/capability.h>

#include "lemon.h"

extern int dump(const struct options *restrict opts, const struct ram_regions *restrict ram_regions, int (*write_f)(void *restrict, const void *restrict, const unsigned long), void *restrict args);
extern int check_capability(const cap_value_t cap);

/*
 * write_on_disk() - Writes a memory chunks to the disk file descriptor
 * @args: Pointer to the file descriptor
 * @data: Pointer to the buffer to be written
 * @size: Number of bytes to write
 */
static int write_on_disk(void *restrict args, const void *restrict data, const unsigned long size) {
    unsigned long r = 0;
    unsigned long total = 0;

    while(total < size) {
        r = write(*((int *)args), data + total, size - total);
        if(r == -1) {
            if(errno == EINTR) continue;
            perror("Fail to write on dump file");
            return errno;
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
    int ret = 0;

    /* Check CAP_DAC_OVERRIDE, creation of the file can fail without it */
    if(check_capability(CAP_DAC_OVERRIDE) <= 0) {
        WARN("LEMON does not have CAP_DAC_OVERRIDE, it may fail in dump file creation\n");
    }

    /* Open dump file in write mode */
    fd = open(opts->path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if(fd < 0) {
        perror("Failed to open dump file for writing");
        return errno;
    }

    /* Dump! */
    ret = dump(opts, ram_regions, write_on_disk, (void *)&fd);

    if(fd) {
        if(fsync(fd)) { perror("Fail to finalize writes on dump file"); ret = errno; }
        if(close(fd)) { perror("Fail to close dump file"); ret = errno; }
    }

    return ret;
}
