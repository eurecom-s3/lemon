#ifndef LEMON_H
#define LEMON_H

#include <stdbool.h>
#include <errno.h>

#define STR2(x) #x
#define STR(x) STR2(x)

#define MIN_MAJOR_LINUX         5                       /* Minimium kernel version supported */
#define MIN_MINOR_LINUX         5

#define HUGE_PAGE_SIZE          2 * 1024 * 1024         /* Same for huge pages */
#define DEFAULT_PORT            2304                    /* Default port used for networt dump */

#define WARN(msg, ...) fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__)

enum dump_modes {
    MODE_UNDEFINED = 0,
    MODE_DISK,
    MODE_NETWORK
};

struct options {
    
    /* Modes */
    enum dump_modes dump_mode;

    /* Mutually exclusive options for disk and network dump modes*/
    union {
        /* Disk options */
        char *path;

        struct {
            /* Network options */
            unsigned long address;
            unsigned short port;
        };
    };

    /* Options */
    bool fatal;
    bool raw;
};

struct mem_range {
    unsigned long long start;
    unsigned long long end;
};

struct ram_regions {
    struct mem_range *regions;
    unsigned int num_regions;
};

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

struct lemon_ctx {
    struct options opts;
};

#endif /* LEMON_H */
