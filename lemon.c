#include <stdlib.h>
#include <unistd.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <sys/utsname.h>
#include <sys/capability.h>
#include <sys/queue.h>
#include <string.h>

#include "lemon.h"

/*
 * lemon.c - CLI (argp), process setup, and main orchestration for LEMON.
 *
 * Loads eBPF, toggles kptr_restrict, discovers RAM regions, runs disk or network dump,
 * restores sysctl, and prints a compatibility report block on stderr.
 */

extern int load_ebpf_mem_progs(struct lemon_ctx *restrict ctx);
extern int init_translation(struct lemon_ctx *restrict ctx);
extern int dump_on_disk(const struct lemon_ctx *restrict ctx);
extern int dump_on_net(const struct lemon_ctx *restrict ctx);
extern int check_capability(const struct lemon_ctx *restrict ctx, const cap_value_t cap);
extern int toggle_kptr(struct lemon_ctx *restrict ctx);
extern void cleanup_mem_ebpf(void);
extern void range_list_free(struct ram_regions *list);
extern int check_init_qualcomm(struct lemon_ctx *restrict ctx);

#define LEMON_VERSION  "lemon-" BRANCH "-" VERSION
#define LEMON_DOC "LEMON - An eBPF Memory Dump Tool for x64 and ARM64 Linux and Android\nVersion " LEMON_VERSION

const char *architecture = ARCH;
const char *binary_type = MODE;
const char *lemon_version = LEMON_VERSION;
const bool is_static = STATIC;

struct err_trace_entry _err_trace[ERR_TRACE_MAX];
int _err_trace_count = 0;

const char *lemon_banner =
"+-------------------------------------------------------------------+\n"
"|                                                                   |\n"
"|             _      _____ __  __  ___  _   _                       |\n"
"|            | |    | ____|  \\/  |/ _ \\| \\ | |                      |\n"
"|            | |    |  _| | |\\/| | | | |  \\| |                      |\n"
"|            | |___ | |___| |  | | |_| | |\\  |                      |\n"
"|            |_____||_____|_|  |_|\\___/|_| \\_|                      |\n"
"|                                                                   |\n"
"|   An eBPF Memory Dump Tool for x64 and ARM64 Linux and Android    |\n"
"|                                                                   |\n"
"|   Created by Andrea Oliveri, Marco Cavenati and Stefano De Rosa   |\n"
"|                                                                   |\n"
"+-------------------------------------------------------------------+\n";

/* argp option table: disk/network modes, dump tuning, and advanced switches. */
static const struct argp_option options[] = {
    {0, 0, 0, OPTION_DOC, "Dump modes:", 1},
    {"disk",      'd', "PATH",          0, "Dump on disk", 1},
    {"network",   'n', "ADDRESS",       0, "Dump on remote IP address (default port TCP " STR(DEFAULT_PORT) ")", 1},
    
    {0, 0, 0, OPTION_DOC, "Dump options:", 2},
    {"fatal",     'f', 0,               0, "Interrupt the dump in case of memory read error", 2},
    {"port",      'p', "PORT",          0, "Remote IP destination port", 2},
    {"raw",       'w', 0,               0, "Produce a RAW dump instead of a LiME one", 2},
    
    {0, 0, 0, OPTION_DOC, "Advanced options:", 3},
    {"debug",     'g', 0,               0, "Enable debug prints ", 3},
    {"xdp",       'x', 0,               0, "Force the use of XDP instead UPROBE as eBPF trigger", 3},
    {"iomem_user",'u', 0,               0, "Force the read of /proc/iomem instead of kernel struct resource ", 3},
    {"dryrun",    'y', 0,               0, "Simulate a dump (not read the physical memory)", 3},
    {"huge",      'H', 0,               0, "Use huge pages (2MB) instead of 4KB", 3},
    {"qcom",      'q', 0,               0, "Force the use of Qualcomm quirks", 3},
    {"rphy",     'r', "ADDRESS:SIZE",  0, "Dump physical pages range", 3},
    {"rvirt",    'v', "ADDRESS:SIZE",  0, "Dump virtual pages range", 3},
    {"testrun",  't', 0,               0, "Force the use of BPF_PROG_TEST_RUN as eBPF trigger", 3},

    {0}
};
static const char doc[] = LEMON_DOC;

/*
 * parse_mem_range() - Parses an "ADDR:SIZE" string into a mem_range.
 * @arg:   Input string in the form "ADDR:SIZE" (both values may be decimal or 0x-prefixed hex).
 * @range: Output mem_range with start = ADDR and end = ADDR + SIZE (half-open).
 *
 * Returns 0 on success, EINVAL if the format is invalid or parsing fails.
 */
static int parse_mem_range(const bool virtual, const char *arg, struct mem_range *range) {
    char *sep;
    char *endptr;
    unsigned long long addr;
    unsigned long size;

    /* "ADDR:SIZE" with optional 0x hex. */
    sep = strchr(arg, ':');
    if (!sep)
        return EINVAL;

    errno = 0;
    addr = strtoull(arg, &endptr, 0);
    if (errno == ERANGE || endptr != sep)
        return EINVAL;

    errno = 0;
    size = strtoul(sep + 1, &endptr, 0);
    if (errno == ERANGE || *endptr != '\0' || size == 0)
        return EINVAL;

    /* mem_range uses half-open [start, end); end is first byte past the region. */
    range->start = addr;
    range->end   = addr + size;
    range->virtual = virtual;

    return 0;
}

/*
 * parse_opt() - Argument parser callback for argp
 * @key: Option key
 * @arg: Option argument string
 * @state: Argp parser state
 *
 * Parses command-line arguments into the options struct. Validates IP address and port,
 * enforces mutual exclusivity between disk and network modes, and ensures required options
 * are present based on the selected mode.
 * Returns 0 on success or ARGP_ERR_UNKNOWN for unrecognized options.
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct options *opts = state->input;
    struct in_addr addr;
    long port;
    char *end;

    switch (key) {
        /* --- Dump destination (mutually exclusive) --- */
        case 'd':
            if (opts->dump_mode != MODE_UNDEFINED) {
                 argp_error(state, "Options -d and -n are mutually exclusive");
            }
            opts->path = arg;
            opts->dump_mode = MODE_DISK;
            break;

        case 'n':
            if (opts->dump_mode != MODE_UNDEFINED) {
                argp_error(state, "Options -d and -n are mutually exclusive");
            }
            	        
            if (inet_pton(AF_INET, arg, &addr) != 1) {
                argp_error(state, "Invalid IP address format");
            }
            opts->address = addr.s_addr;
            opts->dump_mode = MODE_NETWORK;
            break;

        /* --- Dump behavior --- */
        case 'f':
            opts->fatal = true;
            break;

        case 'p':
            errno = 0;
            port = strtol(arg, &end, 10);
            if (errno != 0 || *arg == '\0' || *end != '\0' || port < 1 || port > 65535) {
                argp_error(state, "Port must be between 1 and 65535");
            }
            opts->port = (unsigned short)port;
            break;

        case 'w':
            opts->raw = true;
            break;
        
        case 'y':
            opts->simulate = true;
            break;
        
        case 'x':
            opts->force_xdp = true;
            break;

        case 't':
            opts->force_test_run = true;
            break;

        case 'u':
            opts->force_iomem_user = true;
            break;
        
        /* --- Advanced / hardware --- */
        case 'g':
            opts->debug = true;
            break;

        case 'H':
            opts->use_huge_pages = true;
            break;
        
        case 'q':
            opts->force_qualcomm = true;
            break;

        case 'r':
        case 'v':
            if(parse_mem_range(key == 'v'? true:false, arg, &opts->forced_range))
                argp_error(state, "Invalid memory range argument");
            opts->force_dump_range = true;
            break;

        case ARGP_KEY_END:
            /* Port option is only valid in network dump mode */
            if(opts->dump_mode != MODE_NETWORK && opts->port != DEFAULT_PORT) argp_error(state, "-p can be used only in network dump mode");

            /* Ensure at least one mode is specified */
            if (opts->dump_mode == MODE_UNDEFINED) {
                argp_error(state, "Either disk mode or network mode must be specified");
            }

            /* Qualcomm path uses struct page metadata; incompatible with huge granule. */
            if (opts->use_huge_pages && opts->force_qualcomm) {
                argp_error(state, "Qualcomm quirks are not possible using huge pages");
            }

            if (opts->force_xdp && opts->force_test_run)
                argp_error(state, "Options -x and -t are mutually exclusive");
            break;
        
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/*
 * check_kernel_version() - Parse uname.release and record ctx->kern_info
 * @ctx: kern_info filled from uname(2).
 *
 * Warns if below MIN_MAJOR/MIN_MINOR but still returns 0.
 * Returns 0 on success, or a positive errno-style code if uname fails.
 */
static int check_kernel_version(struct lemon_ctx *restrict ctx) {
    struct utsname buffer;
    int major = 0, minor = 0, patch = 0;

    if (uname(&buffer) != 0) {
        RETURN_ERRNO("Fail to get Linux kernel version");
    }
    if(sscanf(buffer.release, "%d.%d.%d", &major, &minor, &patch) != 3) {
        ERR("Fail to parse Linux version");
        return EINVAL;
    }
    DBG("Kernel version: %d.%d.%d", major, minor, patch);

    memcpy(&ctx->kern_info, &buffer, sizeof(struct utsname));

    if (!((major > MIN_MAJOR_LINUX) || ((major == MIN_MAJOR_LINUX) && (minor >= MIN_MINOR_LINUX))))
        WARN("Detected Linux version is not supported by LEMON. Minimum required version: %d.%d. Try to continue anyway...", MIN_MAJOR_LINUX, MIN_MINOR_LINUX);

    return 0;
}

/*
 * getprop_cmd() - Read one Android property via getprop(1)
 * @ctx: Used only for DBG().
 * @name: Property key (must be trusted / caller-supplied literal).
 * @value: Out buffer, always NUL-terminated on success.
 * @value_size: Size of @value including NUL.
 *
 * Returns 0 on success, or EINVAL/ENOENT/EIO on failure.
 */
static int getprop_cmd(const struct lemon_ctx *restrict ctx, char *name, char *value, size_t value_size)
{
    char cmd[256];
    char buf[256];

    if (!name || !value || value_size == 0)
        return EINVAL;

    snprintf(cmd, sizeof(cmd), "getprop %s", name);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return ENOENT;

    /* getprop prints one line or nothing; treat EOF as missing property. */
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return EIO;
    }
    pclose(fp);

    buf[strcspn(buf, "\n")] = '\0';  /* Strip trailing newline if present. */

    /* getprop returns an empty line for unset properties. */
    if (buf[0] == '\0')
        return EINVAL;

    strncpy(value, buf, value_size - 1);
    value[value_size - 1] = '\0';

    DBG("getprop_cmd %s: %s", name, value);

    return 0;
}

/*
 * collect_android_info() - Detect Android and fill manufacturer / SoC strings
 * @ctx: Sets is_android and optional identity fields used by Qualcomm detection.
 *
 * Returns 0 on non-Android or on success; errno-style code if getprop_cmd fails.
 */
static int collect_android_info(struct lemon_ctx *restrict ctx) {
    int ret;
    ctx->is_android = access("/system/bin/getprop", X_OK) == 0 || access("/vendor/bin/getprop", X_OK) == 0;
    DBG("Android: %d", ctx->is_android);
    if(!ctx->is_android)
        return 0;

    /* Extract Android related info */
    if((ret = getprop_cmd(ctx, "ro.product.manufacturer", ctx->manufacturer, MAX_INFO_FIELD)) ||
       (ret = getprop_cmd(ctx, "ro.product.model", ctx->model, MAX_INFO_FIELD)) ||
       (ret = getprop_cmd(ctx, "ro.soc.manufacturer", ctx->soc_manufacturer, MAX_INFO_FIELD)) ||
       (ret = getprop_cmd(ctx, "ro.soc.model", ctx->soc_model, MAX_INFO_FIELD)) ||
       (ret = getprop_cmd(ctx, "ro.build.fingerprint", ctx->fingerprint, MAX_INFO_FIELD)))
        return ret;

    return 0;
}

/*
 * init_context() - Zero ctx and apply defaults (empty RAM list, default port, kptr sentinel).
 */
static int init_context(struct lemon_ctx *restrict ctx) {
    memset(ctx, 0x00, sizeof(struct lemon_ctx));

    ctx->opts.dump_mode = MODE_UNDEFINED;
    ctx->opts.port = DEFAULT_PORT;
    ctx->original_kptr = -1;    /* Sentinel: kptr not yet read. */
    TAILQ_INIT(&ctx->ram_regions);

    return 0;
}

/*
 * collect_system_info() - Granule, Android props, caps, kernel version, eBPF capability hints
 * @ctx: Populated for later stages and the compatibility report.
 *
 * Returns 0 (continues after kernel version errors with a warning).
 */
static int collect_system_info(struct lemon_ctx *restrict ctx) {
    int ret;

    ctx->granule = ctx->opts.use_huge_pages ? HUGE_PAGE_SIZE : PAGE_SIZE;

    if((ret = collect_android_info(ctx))) {
        ERR("Error in Android init function");
        return ret;
    }

    /* Snapshot capabilities once; reused by every check_capability() call. */
    ctx->capabilities = cap_get_proc();
    if (ctx->capabilities == NULL) {
        RETURN_ERRNO("Fail to get process capabilities");
    }

    if(getuid() != 0)
        WARN("LEMON is not running as root. Try to continue anyway...");
    else
        ctx->run_as_root = true;

    /* Kernel version is informational; non-fatal if it can't be parsed. */
    if((ret = check_kernel_version(ctx))) {
        ERR("Failed to determine kernel version (error %d). Continuing with incomplete info...", ret);
    }

    /* CAP_BPF or CAP_SYS_ADMIN required for bpf() syscall on kernels >= 5.8. */
    if((check_capability(ctx, CAP_BPF) != 1) && (check_capability(ctx, CAP_SYS_ADMIN) != 1)) {
        WARN("LEMON does not have CAP_BPF nor CAP_SYS_ADMIN to load the eBPF component. Try to continue anyway...");
    }

    return 0;
}

/*
 * cleanup_context() - cap_free() and free all mem_range nodes in ram_regions
 * @ctx: Must match the context used for the run.
 *
 * Returns 0 or errno from cap_free (range_list_free still runs).
 */
static int cleanup_context(struct lemon_ctx *ctx) {
    int ret = 0;

    if(ctx->capabilities) {
        if(cap_free(ctx->capabilities)) {
            ret = errno;
            ERRNO("Fail to free capabilities struct");
        }
    }

    if(ctx->linux_banner) free(ctx->linux_banner);

    range_list_free(&ctx->ram_regions);

    return ret;
}

/*
 * init_socs_quirks() - SoC-specific setup (Qualcomm secure page / vmemmap).
 */
static int init_socs_quirks(struct lemon_ctx *ctx) {
    return check_init_qualcomm(ctx);
}

/*
 * print_context_report() - Emit KEY=value lines for compatibility triage
 * @ctx: Current run configuration and discovered hardware/kernel facts.
 * @dump_status: Main return code (0 success, non-zero errno-style or EXIT_FAILURE).
 */
static void print_context_report(const struct lemon_ctx *restrict ctx, int dump_status) {
    const char *trigger_str;
    struct mem_range *range;
    int region_count = 0;
    unsigned long long total_size = 0;

    switch (ctx->ebpf_trigger) {
        case UPROBE:        trigger_str = "uprobe";   break;
        case XDP:           trigger_str = "xdp";      break;
        case PROG_TEST_RUN: trigger_str = "test_run"; break;
        default:            trigger_str = "none";     break;
    }

    /* Walk RAM list for TOTAL_RAM_SIZE; ranges are half-open [start,end). */
    TAILQ_FOREACH(range, &ctx->ram_regions, entries) {
        region_count++;
        total_size += range->end - range->start;
    }

    fprintf(stderr,
        "\n"
        "Post this output on the LEMON site to improve the compatibility table.\n"
        "\n"
        "--- 8< --- CUT HERE --- 8< ---\n"
        "LEMON_VERSION=%s\n"
        "ARCH=%s\n"
        "BUILD_MODE=%s\n"
        "STATIC=%d\n"
        "KERNEL_RELEASE=%s\n"
        "BANNER=%s\n"
        "RUN_AS_ROOT=%u\n"
        "ANDROID=%u\n"
        "QUALCOMM=%u\n"
        "CORE_SUPPORTED=%u\n"
        "EBPF_TRIGGER=%s\n"
        "VA_BITS=%lu\n"
        "VA_BITS_CONFIG=%lu\n"
        "SPARSEMEM_VMEMMAP=%c\n"
        "PAGE_SIZE=%d\n"
        "GRANULE=%d\n"
        "DUMP_MODE=%s\n"
        "RAM_REGIONS=%d\n"
        "TOTAL_RAM_SIZE=%llu\n",
        lemon_version,
        architecture,
        binary_type,
        is_static,
        ctx->kern_info.release,
        ctx->linux_banner ? ctx->linux_banner : "",
        ctx->run_as_root,
        ctx->is_android,
        ctx->is_qualcomm,
        ctx->is_core_supported,
        trigger_str,
        ctx->va_bits,
        ctx->va_bits_config,
        ctx->sparsemem_vmap_config ? ctx->sparsemem_vmap_config : '?',
        PAGE_SIZE,
        ctx->granule,
        ctx->opts.dump_mode == MODE_DISK ? "disk" :
            ctx->opts.dump_mode == MODE_NETWORK ? "network" : "undefined",
        region_count,
        total_size
    );

    if (ctx->is_android) {
        fprintf(stderr,
            "MANUFACTURER=%s\n"
            "MODEL=%s\n"
            "SOC_MANUFACTURER=%s\n"
            "SOC_MODEL=%s\n"
            "FINGERPRINT=%s\n",
            ctx->manufacturer,
            ctx->model,
            ctx->soc_manufacturer,
            ctx->soc_model,
            ctx->fingerprint
        );
    }

    fprintf(stderr,
        "DUMP_STATUS=%s\n"
        "DUMP_ERROR=%d\n",
        dump_status == 0 ? "success" : "fail",
        dump_status
    );

    fprintf(stderr, "ERROR_TRACE_COUNT=%d\n", _err_trace_count);
    for (int i = 0; i < _err_trace_count; i++)
        fprintf(stderr, "ERROR_TRACE_%d=%s:%s:%d\n",
                i, _err_trace[i].func, _err_trace[i].file, _err_trace[i].line);

    fprintf(stderr, "--- 8< --- CUT HERE --- 8< ---\n");
}

/*
 * main() - Parse argv, validate environment, run dump pipeline, always print report
 * @argc: Standard argc.
 * @argv: Standard argv.
 *
 * Returns dump status (0 on success, EXIT_FAILURE or errno-style on error paths).
 */
int main(int argc, char **argv) {
    struct lemon_ctx ctx;
    struct argp argp = {options, parse_opt, "", doc};
    int ret = EXIT_SUCCESS;

    /* Baseline ctx: defaults before argp mutates opts. */
    if(init_context(&ctx)) {
        ERR("Failed to initialize main context");
        return EXIT_FAILURE;
    }

    /* Parse the arguments */
    argp_parse(&argp, argc, argv, 0, 0, &ctx.opts);

    /* Banner :D */
    printf("%s", lemon_banner);
    fflush(stdout);

    /* Collect system info */
    if(collect_system_info(&ctx)) {
        ERR("Failed to collect system info");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* Probe bpf() syscall; ENOSYS means no eBPF in this kernel. */
    errno = 0;
    bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, NULL, NULL, 0, NULL);
    if(errno == ENOSYS) {
        ERR("eBPF not supported by this kernel");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    #ifdef CORE
        /* Check for eBPF CORE support */
        struct btf *vmlinux_btf = btf__load_vmlinux_btf();
        if (!vmlinux_btf) {
            ERR("eBPF CO-RE not supported by this kernel. Try to use no CO-RE version.");
            ret = EXIT_FAILURE;
            goto cleanup;
        }
        btf__free(vmlinux_btf);
        ctx.is_core_supported = true;
    #endif

    /* Load eBPF progs that read memory */
    if((ret = load_ebpf_mem_progs(&ctx))) goto cleanup;

    /* Disable kptr_restrict if needed */
    if((ret = toggle_kptr(&ctx))) goto cleanup;

    /* Determine the memory dumpable regions */
    if((ret = init_translation(&ctx))) goto cleanup;

    /* Qualcomm init returns 0 (skip), 1 (ok), or errno (>1) on hard failure. */
    if((ret = init_socs_quirks(&ctx)) > 1) goto cleanup;

    /* Dump on a file */
    if(ctx.opts.dump_mode == MODE_DISK) {
        INFO("Start dump on disk");
        if((ret = dump_on_disk(&ctx))) goto cleanup;
    }

    /* Dump using TCP packets */
    else if(ctx.opts.dump_mode == MODE_NETWORK) {
        INFO("Start dump over network");
        if((ret = dump_on_net(&ctx))) goto cleanup;
    }

    cleanup:
        cleanup_mem_ebpf();

        /* Second toggle_kptr restores original kptr_restrict after first call lowered it. */
        if (ctx.original_kptr != -1)
            toggle_kptr(&ctx);

        print_context_report(&ctx, ret);

        cleanup_context(&ctx);

    return ret;
}
