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

/* Constants needed for argparse */
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

    {0}
};
static const char doc[] = LEMON_DOC;

/*
 * parse_mem_range() - Parses an "ADDR:SIZE" string into a mem_range.
 * @arg:   Input string in the form "ADDR:SIZE" (both values may be decimal or 0x-prefixed hex).
 * @range: Output mem_range where start = ADDR and end = ADDR + SIZE - 1.
 *
 * Returns 0 on success, -1 if the format is invalid or parsing fails.
 */
static int parse_mem_range(const bool virtual, const char *arg, struct mem_range *range) {
    char *sep;
    char *endptr;
    unsigned long long addr;
    unsigned long size;

    sep = strchr(arg, ':');
    if (!sep)
        return -1;

    addr = strtoull(arg, &endptr, 0);
    if (endptr != sep)
        return -1;

    size = strtoul(sep + 1, &endptr, 0);
    if (*endptr != '\0' || size == 0)
        return -1;

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

        case 'u':
            opts->force_iomem_user = true;
            break;
        
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

            /* Qualcomm quirks is uncompatible with huge page */
            if (opts->use_huge_pages && opts->force_qualcomm) {
                argp_error(state, "Qualcomm quirks are not possible using huge pages");
            }
            break;
        
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/*
 * check_kernel_version() - Checks if the running Linux kernel version support all the feature requested
 * Return:
 *   1 if kernel version is valid
 *   0 if kernel version does not support all the features
 *   < 0 on failure
 */
static int check_kernel_version(struct lemon_ctx *restrict ctx) {
    struct utsname buffer;
    int major = 0, minor = 0, patch = 0;

    if (uname(&buffer) != 0) {
        ERRNO("Fail to get Linux kernel version");
        return -errno;
    }
    if(sscanf(buffer.release, "%d.%d.%d", &major, &minor, &patch) != 3) {
        ERR("Fail to parse Linux version");
        return -EINVAL;
    }
    DBG("Kernel version: %d.%d.%d", major, minor, patch);

    memcpy(&ctx->kern_info, &buffer, sizeof(struct utsname));

    return (major > MIN_MAJOR_LINUX) || ((major == MIN_MAJOR_LINUX) && (minor >= MIN_MINOR_LINUX));
}

/**
 * Get an Android system property by running:
 *   getprop <name>
 * and capturing stdout.
 *
 * Returns 1 on success, 0 on failure.
 * Output is stored in 'value' (null-terminated, trimmed of newline).
 */
static int getprop_cmd(const struct lemon_ctx *restrict ctx, char *name, char *value, size_t value_size)
{
    char cmd[256];
    char buf[256];

    if (!name || !value || value_size == 0)
        return -EINVAL;

    /* Build the command string */
    snprintf(cmd, sizeof(cmd), "getprop %s", name);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -ENOENT;

    /* Read first line of output */
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return -EIO;
    }
    pclose(fp);

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    /* Empty string means property doesn't exist */
    if (buf[0] == '\0')
        return -EINVAL;

    strncpy(value, buf, value_size - 1);
    value[value_size - 1] = '\0';

    DBG("getprop_cmd %s: %s", name, value);

    return 0;
}

/* Look for mandatory android */
static int collect_android_info(struct lemon_ctx *restrict ctx) {
    ctx->is_android = access("/system/bin/getprop", X_OK) == 0 || access("/vendor/bin/getprop", X_OK) == 0;
    DBG("Android: %d", ctx->is_android);
    if(!ctx->is_android)
        return 0;

    /* Extract Android related info */
    if(
        getprop_cmd(ctx, "ro.product.manufacturer", ctx->manufacturer, MAX_INFO_FIELD) ||
        getprop_cmd(ctx, "ro.product.model", ctx->model, MAX_INFO_FIELD) || 
        getprop_cmd(ctx, "ro.soc.manufacturer", ctx->soc_manufacturer, MAX_INFO_FIELD) ||
        getprop_cmd(ctx, "ro.soc.model", ctx->soc_model, MAX_INFO_FIELD) ||
        getprop_cmd(ctx, "ro.build.fingerprint", ctx->fingerprint, MAX_INFO_FIELD))
        return 1;
    
    return 0;
}

static int init_context(struct lemon_ctx *restrict ctx) {
    /* Initialize the context the context */
    memset(ctx, 0x00, sizeof(struct lemon_ctx));

    /* Set default values */
    ctx->opts.dump_mode = MODE_UNDEFINED;
    ctx->opts.port = DEFAULT_PORT;
    ctx->original_kptr = -1;
    TAILQ_INIT(&ctx->ram_regions);

    return 0;
}

static int collect_system_info(struct lemon_ctx *restrict ctx) {
    /* Collect system info*/
    int ret;

    /* Set granule size for dump */
    if(ctx->opts.use_huge_pages)
        ctx->granule = HUGE_PAGE_SIZE;
    else
        ctx->granule = PAGE_SIZE;
 
    /* Init Android fields */
    if((ret = collect_android_info(ctx))) {
        ERR("Error in Android init function");
        return ret;
    }

    /* Get process capabilities */
    ctx->capabilities = cap_get_proc();
    if (ctx->capabilities == NULL) {
        ERRNO("Fail to get process capabilities");
        return errno;
    }

    /* Check if is running as root */
    if(getuid() != 0) {
        WARN("LEMON is not running as root. Try to continue anyway...");
    }
    else ctx->run_as_root = true;
    

    /* Check Linux version */
    if(check_kernel_version(ctx) != 1) {
        WARN("Detected Linux version is not supported by LEMON. Minimum required version: %d.%d. Try to continue anyway...", MIN_MAJOR_LINUX, MIN_MINOR_LINUX);
    }

    /* Check if can load eBPF programs */
    if((check_capability(ctx, CAP_BPF) <= 0) && (check_capability(ctx, CAP_SYS_ADMIN) <= 0)) {
        WARN("LEMON does not have CAP_BPF nor CAP_SYS_ADMIN to load the eBPF component. Try to continue anyway...");
    }

    return 0;
}

static int cleanup_context(struct lemon_ctx *ctx) {
    int ret = 0;
    
    if(ctx->capabilities) {
        if((ret = cap_free(ctx->capabilities))) {
            ERRNO("Fail to free capabilities struct");
            return errno;
        };
    }

    range_list_free(&ctx->ram_regions);

    return ret;
}

static int init_socs_quirks(struct lemon_ctx *ctx) {
    int ret;
    if((ret = check_init_qualcomm(ctx)) < 0) return 1;

    return 0;
}

int main(int argc, char **argv) {
    struct lemon_ctx ctx;
    struct argp argp = {options, parse_opt, "", doc};
    int ret = EXIT_SUCCESS;

    /* Init the main context */
    if(init_context(&ctx)) {
        ERR("Failed to initialize main context");
        return EXIT_FAILURE;
    }

    /* Parse the arguments */
    argp_parse(&argp, argc, argv, 0, 0, &ctx.opts);

    /* Collect system info */
    if(collect_system_info(&ctx)) {
        ERR("Failed to collect system info");
        return EXIT_FAILURE;
    }

    /* Check for eBPF support */
    errno = 0;
    int bpf_ret = bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, NULL, NULL, 0, NULL);
	if(bpf_ret <0 && errno == ENOSYS) {
        ERR("eBPF not supported by this kernel");
        return EXIT_FAILURE;
    }

    #ifdef CORE
        /* Check for eBPF CORE support */
        struct btf *vmlinux_btf = btf__load_vmlinux_btf();
        if (!vmlinux_btf) {
            ERR("eBPF CO-RE not supported by this kernel. Try to use no CO-RE version.");
            return EXIT_FAILURE;
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

    /* Init SoCs quirks */
    if((ret = init_socs_quirks(&ctx))) goto cleanup;

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

    /* Cleanup: close BPF object */
    cleanup:
        cleanup_mem_ebpf();

        /* Restore kptr_restrict if needed */
        toggle_kptr(&ctx);

        cleanup_context(&ctx);

    return ret; // TODO rework all the ret values handling
}
