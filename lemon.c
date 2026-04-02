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
extern int check_capability(const cap_value_t cap);
extern int toggle_kptr(void);
extern void cleanup_mem_ebpf(void);

/* Constants needed for argparse */
static const struct argp_option options[] = {
    {0, 0, 0, OPTION_DOC, "Dump modes:", 1},
    {"disk",      'd', "PATH",          0, "Dump on disk", 1},
    {"network",   'n', "ADDRESS",       0, "Dump on remote IP address (default port TCP " STR(DEFAULT_PORT) ")", 1},
    
    {0, 0, 0, OPTION_DOC, "Behavior options:", 2},
    {"fatal",     'f', 0,               0, "Interrupt the dump in case of memory read error", 2},
    {"port",      'p', "PORT",               0, "Remote IP destination port", 2},
    {"raw",       'w', 0,               0, "Produce a RAW dump instead of a LiME one", 2},
    
    {0}
};
static const char doc[] = "LEMON - An eBPF Memory Dump Tool for x64 and ARM64 Linux and Android";

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
            if(opts->dump_mode != MODE_NETWORK) {
                argp_error(state, "-p can be used only in network dump mode");
            }
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

        case ARGP_KEY_END:
            /* Ensure at least one mode is specified */
            if (opts->dump_mode == MODE_UNDEFINED) {
                argp_error(state, "Either disk mode or network mode must be specified");
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

int main(int argc, char **argv) {
    struct ram_regions ram_regions;
    struct options opts = {0};
    struct argp argp = {options, parse_opt, "", doc};
    int ret = EXIT_SUCCESS;

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

    /* Load eBPF progs that read memory */
    if((ret = load_ebpf_mem_progs())) return ret;

    /* Disable kptr_restrict if needed */
    if((ret = toggle_kptr())) return ret;

    /* Determine the memory dumpable regions */
    if((ret = init_translation(&ram_regions))) goto cleanup;

    /* Dump on a file */
    if(opts.dump_mode == MODE_DISK) {
        if((ret = dump_on_disk(&opts, &ram_regions))) goto cleanup;
    }

    /* Dump using TCP packets */
    else if(opts.dump_mode == MODE_NETWORK) { 
        if((ret = dump_on_net(&opts, &ram_regions))) goto cleanup;
    }

    /* Cleanup: close BPF object */
    cleanup:
        cleanup_mem_ebpf();

        /* Restore kptr_restrict if needed */
        if((ret = toggle_kptr())) return ret;

    return ret; // TODO rework all the ret values handling
}
