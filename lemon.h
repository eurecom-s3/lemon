#ifndef LEMON_H
#define LEMON_H

#include <stdbool.h>
#include <errno.h>
#include <sys/queue.h>

#define MIN_MAJOR_LINUX         5                       /* Minimium kernel version supported */
#define MIN_MINOR_LINUX         5

// TODO: to support secure pages we need to go page by page, make this a bit cleaner
#define HUGE_PAGE_SIZE          4096//2 * 1024 * 1024   /* Same for huge pages */
#define DEFAULT_PORT            2304                    /* Default port used for networt dump */

#define WARN(msg, ...) fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__)

struct options {
    /* Modes */
    bool disk_mode;
    bool network_mode;

    /* Disk options */
    char *path;

    /* Network options */
    unsigned long address;
    unsigned short port;

    /* Options */
    bool realtime;
    bool fatal;
    bool raw;
};

struct mem_range {
    TAILQ_ENTRY(mem_range) entries;
    unsigned long long start;
    unsigned long long end;
};

TAILQ_HEAD(ram_regions, mem_range);

typedef struct __attribute__((packed)) {
    unsigned int magic;
    unsigned int version;
    unsigned long long s_addr;
    unsigned long long e_addr;
    unsigned char reserved[8];
} lime_header;

struct read_mem_result {
    int ret_code;
    unsigned char buf[HUGE_PAGE_SIZE];
};

struct read_mem_args {
    unsigned long long addr; 
    unsigned long size;
};

#endif /* LEMON_H */
