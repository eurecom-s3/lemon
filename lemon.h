#ifndef LEMON_H
#define LEMON_H

#include <stdbool.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/capability.h>
#include <sys/queue.h>

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
#define ERR(msg, ...) do { \
    fprintf(stderr, "[ERROR] " msg "\n", ##__VA_ARGS__); \
    _err_trace_push(__func__, __FILE__, __LINE__); \
} while (0)
#define ERRNO(msg, ...) do { \
    fprintf(stderr, "[ERROR] " msg ": %s\n", ##__VA_ARGS__, strerror(errno)); \
    _err_trace_push(__func__, __FILE__, __LINE__); \
} while (0)

#define ERR_TRACE_MAX 16

struct err_trace_entry {
    const char *func;
    const char *file;
    int line;
};

extern struct err_trace_entry _err_trace[];
extern int _err_trace_count;

static inline void _err_trace_push(const char *func, const char *file, int line) {
    if (_err_trace_count < ERR_TRACE_MAX)
        _err_trace[_err_trace_count++] =
            (struct err_trace_entry){ .func = func, .file = file, .line = line };
}

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)          \
    for ((var) = TAILQ_FIRST(head);                         \
         (var) && ((tvar) = TAILQ_NEXT(var, field), 1);    \
         (var) = (tvar))
#endif

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

struct mem_range {
    TAILQ_ENTRY(mem_range) entries;
    bool virtual;
    unsigned long long start;
    unsigned long long end;
};
TAILQ_HEAD(ram_regions, mem_range);

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
        unsigned int use_huge_pages:1;
        unsigned int force_qualcomm:1;
        unsigned int force_dump_range:1;
    };

    struct mem_range forced_range;
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
    uintptr_t iomem_resource; /* Address of root of struct resources list (physical memory regions list) */
    int granule;

    struct {
        unsigned int run_as_root: 1;
        unsigned int is_android: 1;
        unsigned int is_core_supported: 1;
        unsigned int is_qualcomm:1;
    };
    enum ebpf_trigger ebpf_trigger;
    char sparsemem_vmap_config;

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
    uintptr_t mem_section;

    // TODO: Add SELinux context info
};

#endif /* LEMON_H */
