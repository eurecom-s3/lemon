#ifndef LEMON_H
#define LEMON_H

#include <stdbool.h>
#include <errno.h>

#define MIN_MAJOR_LINUX         5 /* Minimium kernel version supported */
#define MIN_MINOR_LINUX         5

#define HUGE_PAGE_SIZE          2 * 1024 * 1024         /* Same for huge pages */
#define DEFAULT_PORT            2304                    /* Default port used for networt dump */
#define UDP_MAX_PAYLOAD         1024                    /* Maximum payload for UDP socket */

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
    bool udp;

    /* Options */
    bool realtime;
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

#endif /* LEMON_H */
