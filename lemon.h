#ifndef LEMON_H
#define LEMON_H

#include <stdbool.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/capability.h>

#include "ebpf/mem.ebpf.h"

#define STR2(x) #x
#define STR(x) STR2(x)

#define MIN_MAJOR_LINUX         5                       /* Minimium kernel version supported */
#define MIN_MINOR_LINUX         5

#define DEFAULT_PORT            2304                    /* Default port used for networt dump */

#define PROP_VALUE_MAX          92
#define MAX_INFO_FIELD          256

#define DBG(msg, ...) do { if ((ctx->opts.debug) == true) fprintf(stderr, "[DBG] " msg "\n", ##__VA_ARGS__); } while (0)
#define INFO(msg, ...) fprintf(stderr, "[INFO] " msg "\n", ##__VA_ARGS__)
#define WARN(msg, ...) fprintf(stderr, "[WARNING] " msg "\n", ##__VA_ARGS__)
#define ERR(msg, ...)  fprintf(stderr, "[ERROR] " msg "\n", ##__VA_ARGS__)
#define ERRNO(msg, ...)  fprintf(stderr, "[ERROR] " msg ": %s\n", ##__VA_ARGS__, strerror(errno))


enum dump_modes {
    MODE_UNDEFINED = 0,
    MODE_DISK,
    MODE_NETWORK
};

enum ebpf_trigger {
    TRIGGER_UNDEFINED = 0,
    UPROBE,
    XDP
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
    bool debug;
    struct {
        unsigned int fatal: 1;
        unsigned int raw: 1;
        unsigned int simulate: 1;
        unsigned int force_xdp: 1;
        unsigned int force_iomem_user: 1;
        unsigned int use_huge_pages:1 ;
    };
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

struct lemon_ctx {
    struct options opts;
    struct ram_regions ram_regions;
    int granule;

    struct {
        unsigned int run_as_root: 1;
        unsigned int is_android: 1;
        unsigned int is_core_supported: 1;
    };
    enum ebpf_trigger ebpf_trigger;

    struct utsname kern_info;
    cap_t capabilities;

    char manufacturer[MAX_INFO_FIELD];
    char model[MAX_INFO_FIELD];
    char soc_manufacturer[MAX_INFO_FIELD];
    char soc_model[MAX_INFO_FIELD];
    char fingerprint[MAX_INFO_FIELD];

    int original_kptr;
    unsigned long va_bits;
    unsigned long va_bits_config;

    /* Offset used to perform physical to virtual address translation in x86 and ARM64 */
    #ifdef __TARGET_ARCH_x86
        uintptr_t v2p_offset;
    #elif __TARGET_ARCH_arm64
        int64_t v2p_offset;
    #endif

    // TODO: Add SELinux context info
    // TODO: when qualcomm and other sok NO HUGE PAGE
};


#endif /* LEMON_H */
