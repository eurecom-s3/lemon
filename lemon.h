#ifndef LEMON_H
#define LEMON_H

/*
 * lemon.h - Shared types, logging macros, and struct lemon_ctx for LEMON.
 *
 * DBG()/ERR()/ERRNO()/RETURN_ERRNO use a visible `ctx` in scope (passed from callers).
 */

#include <stdbool.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/capability.h>
#include <sys/queue.h>

#include "ebpf/mem.ebpf.h"

/* Helpers to stringify an expanded macro value in a string literal. */
#define STR2(x) #x
#define STR(x) STR2(x)

#define MIN_MAJOR_LINUX         5       /* Minimum supported Linux major version. */
#define MIN_MINOR_LINUX         5       /* Minimum supported Linux minor version. */

#define DEFAULT_PORT            2304    /* Default TCP port for the network dump receiver. */

#define PROP_VALUE_MAX          92      /* Android property value limit (system default). */
#define MAX_INFO_FIELD          256     /* Max bytes for device identity strings in lemon_ctx. */

/*
 * Logging macros.
 *
 * DBG  - Emits only when ctx->opts.debug is set; expects a local `ctx` in scope.
 * INFO - Unconditional informational message.
 * WARN - Non-fatal warning.
 * ERR  - Error with source location pushed onto the err_trace ring.
 * ERRNO - ERR variant that appends strerror(errno) to the message.
 * RETURN_ERRNO - Saves errno, calls ERRNO(), then returns the saved value.
 *                Safe to use even when fprintf might clobber errno.
 */
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
#define RETURN_ERRNO(msg, ...) do { \
    int _saved = errno; \
    ERRNO(msg, ##__VA_ARGS__); \
    return _saved; \
} while (0)

/* Maximum depth of the error call-site ring buffer printed in the report. */
#define ERR_TRACE_MAX 16

/* One frame stored by ERR/ERRNO for the compatibility report. */
struct err_trace_entry {
    const char *func;   /* __func__ of the call site. */
    const char *file;   /* __FILE__ of the call site. */
    int line;           /* __LINE__ of the call site. */
};

extern struct err_trace_entry _err_trace[];
extern int _err_trace_count;

/*
 * _err_trace_push() - Append one call-site frame to the err_trace ring
 *
 * Silently drops frames once ERR_TRACE_MAX is reached; never overwrites
 * the oldest entry (so the first error chain is always preserved).
 */
static inline void _err_trace_push(const char *func, const char *file, int line) {
    if (_err_trace_count < ERR_TRACE_MAX)
        _err_trace[_err_trace_count++] =
            (struct err_trace_entry){ .func = func, .file = file, .line = line };
}

/*
 * TAILQ_FOREACH_SAFE - Iterate a TAILQ while allowing removal of the current node.
 *
 * Not in all sys/queue.h versions. Uses a lookahead variable @tvar to store
 * the successor before the loop body can unlink @var.
 */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)          \
    for ((var) = TAILQ_FIRST(head);                         \
         (var) && ((tvar) = TAILQ_NEXT(var, field), 1);    \
         (var) = (tvar))
#endif

/* Where dump output is written. */
enum dump_modes {
    MODE_UNDEFINED = 0,
    MODE_DISK,
    MODE_NETWORK
};

/* How kernel memory reads are triggered after load_ebpf_mem_progs(). */
enum ebpf_trigger {
    TRIGGER_UNDEFINED = 0,
    UPROBE,
    XDP,
    PROG_TEST_RUN
};

/* One contiguous range [start, end) in physical or virtual space. */
struct mem_range {
    TAILQ_ENTRY(mem_range) entries;
    bool virtual;
    unsigned long long start;
    unsigned long long end;
};
TAILQ_HEAD(ram_regions, mem_range);

/* CLI options and mode-specific fields (path vs address/port union). */
struct options {

    enum dump_modes dump_mode;  /* Disk, network, or undefined (validated at ARGP_KEY_END). */

    /*
     * Destination: path for disk mode, or IPv4 address + port for network mode.
     * Only the active member is valid after argument parsing.
     */
    union {
        char *path;             /* -d PATH: output file path. */

        struct {
            unsigned long address;  /* -n ADDRESS: destination IP (network byte order). */
            unsigned short port;    /* -p PORT: destination TCP port (default DEFAULT_PORT). */
        };
    };

    bool debug;                     /* -g: enable [DBG] output on stderr. */
    struct {
        unsigned int fatal: 1;          /* -f: abort dump on first read error. */
        unsigned int raw: 1;            /* -w: raw dump (no LiME headers). */
        unsigned int simulate: 1;       /* -y: dry run, skip all memory reads. */
        unsigned int force_xdp: 1;      /* -x: force XDP trigger (skip uprobe attempt). */
        unsigned int force_iomem_user: 1; /* -u: read /proc/iomem instead of kernel struct resource. */
        unsigned int use_huge_pages: 1; /* -H: 2 MB granule instead of 4 KB. */
        unsigned int force_qualcomm: 1; /* -q: force Qualcomm secure-page detection. */
        unsigned int force_dump_range: 1; /* -r/-v: dump a single physical/virtual range. */
        unsigned int force_test_run: 1; /* -t: force BPF_PROG_TEST_RUN trigger. */
    };

    struct mem_range forced_range;  /* Address and size from -r/-v; only valid when force_dump_range. */
};

/*
 * LiME segment header prepended before each RAM region in LiME format dumps.
 * Not written when ctx->opts.raw is set.  Packed to match the on-disk layout
 * expected by LiME-aware analysis tools (e.g. volatility, lime-forensics).
 */
typedef struct __attribute__((packed)) {
    unsigned int magic;             /* 0x4C694D45 ("LiME"). */
    unsigned int version;           /* 1. */
    unsigned long long s_addr;      /* First physical byte of this segment. */
    unsigned long long e_addr;      /* Last physical byte of this segment (inclusive). */
    unsigned char reserved[8];      /* Zeroed. */
} lime_header;

/* Global runtime state for one LEMON invocation. */
struct lemon_ctx {
    struct options opts;            /* Parsed CLI options. */
    struct ram_regions ram_regions; /* List of physical/virtual ranges to dump (half-open [start,end)). */
    uintptr_t iomem_resource;       /* Kernel VA of the root struct resource (iomem_resource symbol). */
    int granule;                    /* Chunk size for dump_region(): PAGE_SIZE or HUGE_PAGE_SIZE. */

    /* Detected system properties (single-bit flags). */
    struct {
        unsigned int run_as_root: 1;      /* getuid() == 0 at startup. */
        unsigned int is_android: 1;       /* /system/bin/getprop is executable. */
        unsigned int is_core_supported: 1;/* vmlinux BTF available (btf__load_vmlinux_btf OK). */
        unsigned int is_qualcomm: 1;      /* SoC is Qualcomm; secure-page checks are active. */
    };
    enum ebpf_trigger ebpf_trigger; /* Which trigger path is in use after load_ebpf_mem_progs(). */
    char sparsemem_vmap_config;     /* CONFIG_SPARSEMEM_VMEMMAP value ('y'/'n'/0 if unknown). */

    struct utsname kern_info;       /* From uname(2); release string used in the report. */
    cap_t capabilities;             /* From cap_get_proc(); freed by cleanup_context(). */

    /* Android device identity (populated by collect_android_info; empty on non-Android). */
    char manufacturer[MAX_INFO_FIELD];
    char model[MAX_INFO_FIELD];
    char soc_manufacturer[MAX_INFO_FIELD];
    char soc_model[MAX_INFO_FIELD];
    char fingerprint[MAX_INFO_FIELD];

    int original_kptr;      /* kptr_restrict value at first toggle_kptr() call; -1 if not yet read. */
    unsigned long va_bits;          /* Effective VA bit width (from .kconfig or runtime probe). */
    unsigned long va_bits_config;   /* CONFIG_ARM64_VA_BITS from .kconfig (0 if absent). */

    /* Physical-to-virtual offset: x86_64 uses unsigned linear-map base; arm64 uses signed memstart_addr. */
    #ifdef __TARGET_ARCH_x86
        uintptr_t v2p_offset;   /* page_offset_base from kallsyms. */
    #elif __TARGET_ARCH_arm64
        int64_t v2p_offset;     /* memstart_addr from kallsyms (negative on typical systems). */
    #endif
    uintptr_t mem_section;  /* Kernel VA of mem_section[] array; used by Qualcomm vmemmap logic. */
};

#endif /* LEMON_H */
