#include <stdlib.h>
#include <unistd.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <sys/utsname.h>
#include <sys/capability.h>

#include "lemon.h"

extern int load_ebpf_mem_progs(void);
extern int init_translation(struct ram_regions *restrict ram_regions);
extern int dump_on_disk(const struct options *restrict opts, const struct ram_regions *restrict ram_regions);
extern int dump_on_net(const struct options *restrict opts, const struct ram_regions *restrict ram_regions);
extern int increase_priority_and_launch_stealers(void);
extern int join_cpu_stealers(void);
extern int check_capability(const cap_value_t cap);
extern int toggle_kptr(void);
extern void cleanup_mem_ebpf(void);

/* Constants needed for argparse */
static const struct argp_option options[] = {
    {"disk",      'd', "PATH",      0, "Dump on disk", 0},
    {"network",   'n', "ADDRESS",   0, "Dump through the network", 1},
    {"port",      'p', "PORT",      0, "Specify port number", 1},
    {"udp",       'u', 0,           0, "Use UDP instead of TCP", 1},
    {"realtime",  'r', 0,           0, "Use realtime priority", 2},
    {"fatal",     'f', 0,           0, "Interrupt the dump in case of memory read error", 2},
    {"raw",       'w', 0,           0, "Produce a RAW dump instead of a LiME one", 2},
    {0}
};
static const char doc[] = "Lemon - An eBPF Memory Dump Tool for x64 and ARM64 Linux and Android";

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
    
    switch (key) {
        case 'n':
	    if (inet_pton(AF_INET, arg, &addr) != 1) {
                argp_error(state, "Invalid IP address format");
            }
            opts->address = addr.s_addr;
            opts->network_mode = true;
            break;
        case 'p':
            opts->port = atoi(arg);
            if (opts->port <= 0 || opts->port > 65535) {
                argp_error(state, "Port must be between 1 and 65535");
            }
            break;
        case 'd':
            opts->disk_mode = true;
            opts->path = arg;
            break;
        case 'r':
            opts->realtime = true;
            break;
        case 'f':
            opts->fatal = true;
            break;
        case 'u':
            opts->udp = true;
            fprintf(stderr, "To be implemented...\n");
            exit(EXIT_FAILURE);
        case 'w':
            opts->raw = true;
            break;
        case ARGP_KEY_END:
            /* Validate mutual exclusivity of disk vs net dump */
            if (opts->network_mode && opts->disk_mode) {
                argp_error(state, "Disk and network mode are mutually exclusive");
            }
            
            /* Ensure at least one mode is specified */
            if (!opts->network_mode && !opts->disk_mode) {
                argp_error(state, "Either network mode or disk mode must be specified");
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
static int check_kernel_version() {
    struct utsname buffer;
    int major = 0, minor = 0, patch = 0;

    if (uname(&buffer) != 0) {
        perror("Fail to get Linux kernel version");
        return -errno;
    }
    sscanf(buffer.release, "%d.%d.%d", &major, &minor, &patch);
    if(errno) {
        perror("Fail to parse Linux version");
        return -errno;
    }

    return (major > MIN_MAJOR_LINUX) || ((major == MIN_MAJOR_LINUX) && (minor >= MIN_MINOR_LINUX));
}

int main(int argc, char **argv)
{
    struct ram_regions ram_regions;
    struct options opts = {0};
    struct argp argp = {options, parse_opt, "", doc};
    int ret;

    /* Check if is running as root */
    if(getuid() != 0) {
        WARN("LEMON is not running as root.");
    }

    /* Check Linux version */
    if(check_kernel_version() != 1) {
        WARN("Detected Linux version is not supported by LEMON. Minimum required version: %d.%d", MIN_MAJOR_LINUX, MIN_MINOR_LINUX);
    }

    /* Check if can load eBPF programs */
    if((check_capability(CAP_BPF) <= 0) && (check_capability(CAP_SYS_ADMIN) <= 0)) {
        WARN("LEMON does not have CAP_BPF nor CAP_SYS_ADMIN to load the eBPF component");
    }

    /* Check for eBPF support */
    bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, NULL, NULL, 0, NULL);
	if(errno == ENOSYS) {
        fprintf(stderr, "eBPF not supported by this kernel");
        return EXIT_FAILURE;
    }

    #ifdef CORE
        /* Check for eBPF CORE support */
        struct btf *vmlinux_btf = btf__load_vmlinux_btf();
        if (!vmlinux_btf) {
            fprintf(stderr, "eBPF CO-RE not supported by this kernel. Try to use no CO-RE version.");
            return EXIT_FAILURE;
        }
        btf__free(vmlinux_btf);
    #endif

    /* Parse the arguments */
    opts.port = DEFAULT_PORT;
    argp_parse(&argp, argc, argv, 0, 0, &opts);

    /* Increase process priority and lauch stealers */
    if(opts.realtime) {
        ret = increase_priority_and_launch_stealers();
        if(ret) {
            WARN("Failed to increase process priority and launch CPU stealers");
        }
    }

    /* Load eBPF progs that read memory */
    if((ret = load_ebpf_mem_progs())) return ret;

    /* Disable kptr_restrict if needed */
    if((ret = toggle_kptr())) return ret;

    /* Determine the memory dumpable regions */
    if((ret = init_translation(&ram_regions))) goto cleanup;

    /* Dump on a file */
    if(opts.disk_mode) {
        if((ret = dump_on_disk(&opts, &ram_regions))) goto cleanup;
    }

    /* Dump using TCP packets */
    else if(opts.network_mode) { 
        if((ret = dump_on_net(&opts, &ram_regions))) goto cleanup;
    }

    /* Cleanup: close BPF object */
    cleanup:
        cleanup_mem_ebpf();
        join_cpu_stealers();

        /* Restore kptr_restrict if needed */
        if((ret = toggle_kptr())) return ret;

    return EXIT_SUCCESS;
}
