#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/capability.h>
#include <unistd.h>

#include "lemon.h"
#include "ebpf/mem.ebpf.skel.h"

extern int check_capability(const struct lemon_ctx *restrict ctx, const cap_value_t cap);
extern int parse_iomem(struct lemon_ctx *restrict ctx);


/* eBPF memory read program skeleton */
struct mem_ebpf *mem_ebpf_skel;

/* XDP and UDP trigger resources */
int udp_sockfd = -1;
const char *loopback_interface = "lo";
struct bpf_link *bpf_prog_link = NULL;

/* File descriptor and mmap() pointer associated to the eBPF map */
int read_mem_result_fd;
struct read_mem_result *read_mem_result;

#if defined(__TARGET_ARCH_arm64)
   /*
    * @brief Check if memory mapping respects the given address
    * @param addr: The address to check
    *
    * Attempts to mmap a 1-byte region at the specified address. If the mmap operation is successful 
    * and the address is valid (greater than or equal to the specified address) the function returns 
    * true. Otherwise, it returns false.
    * 
    * @return: true if the mmap succeeds at addr, false otherwise.
    */
    static bool is_mmap_respecting_address(void *addr) {
        const size_t size = 1;
        void *mapped_addr = mmap(addr, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapped_addr == MAP_FAILED) {
            return false;
        }
        
        if (munmap(mapped_addr, size) == -1) {
            ERRNO("Failed to munmap");
            return false;
        }

        /* Check if the mapped address is the desired address, also greater is ok */
        if (mapped_addr >= addr) {
            return true;
        } else {
            return false;
        }
    }

   /*
    * @brief Determine the actual virtual address bits for ARM64
    *
    * Determines the number of virtual address bits used by the system on ARM64 
    * by checking the mmap behavior for various address values defined in arch/arm64/Kconfig. 
    * The function first checks the most common virtual address bit settings (48 and 52), 
    * then falls back to testing other possible values (47, 42, 39, 36) if necessary. 
    * @return Number of virtual address bits used (e.g., 48, 52).
    */
    static unsigned long arm64_vabits_actual() {
        unsigned long vabits = 0;

        /* VA_BITS = 48 is probably the most common check it first */
        if (is_mmap_respecting_address((void*)(1ul << (48 - 1)))) {
            if (is_mmap_respecting_address((void*)(1ul << (52 - 1)))) {
                vabits = 52;
            } else {
                vabits = 48;
            }
        } else {
            /* Remaining cases */
            const unsigned long va_bits[] = {47, 42, 39, 36};
            for(int i = 0; i < 4; ++i) {
                if (is_mmap_respecting_address((void*)(1ul << (va_bits[i] - 1)))) {
                    vabits = va_bits[i];
                    break;
                }
            }
        }

        return vabits;
    }
#endif // __TARGET_ARCH_arm64

/*
 * init_mmap() - Initializes a shared memory mapping for reading memory results from eBPF
 *
 * Retrieves the file descriptor for the BPF map and creates a shared memory mapping
 * to allow user space to access the memory read results.
 */
static int init_mmap() {
    
    read_mem_result_fd = bpf_map__fd(mem_ebpf_skel->maps.read_mem_array_map);
    if(read_mem_result_fd < 0)
        return read_mem_result_fd;

    read_mem_result = (struct read_mem_result *)mmap(NULL, sizeof(struct read_mem_result), PROT_READ | PROT_WRITE, MAP_SHARED, read_mem_result_fd, 0);
    if (read_mem_result == MAP_FAILED) {
        return errno;
    }

    return 0;
}

/*
 * init_udp_socket() - Create and configure UDP socket for sending trigger packets
 *
 * Creates a UDP socket for sending XDP trigger packets to the loopback interface.
 * Returns 0 on success, negative errno value on failure.
 */
static int init_udp_socket() {
    struct sockaddr_in local_addr;

    /* Create UDP socket */
    udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        ERRNO("Failed to create UDP socket for XDP trigger");
        return -errno;
    }

    /* Setup local address structure for binding*/
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;

    return 0;
}

/*
 * load_ebpf_mem_progs() - Initialize and attach eBPF programs for memory access
 *
 * Opens, loads, attaches the eBPF programs, and sets up shared memory. 
 * Returns 0 on success or a negative error code on failure.
 */
int load_ebpf_mem_progs(struct lemon_ctx *restrict ctx) {
    int ret, map_fd, key;
    struct bpf_map *kconfig_map;
    struct config_values cfg_vals;
    unsigned long vabits;

    /* Check if we have sufficient capabilities to set RLIMIT_MEMLOCK (required by libbpf...)*/
    if((check_capability(ctx, CAP_PERFMON) <= 0) && (check_capability(ctx, CAP_SYS_ADMIN) <= 0)) {
        WARN("LEMON does not have CAP_PERFMON needed to modify RLIMIT_MEMLOCK");
    }

    /* Open the BPF object file */
    mem_ebpf_skel = mem_ebpf__open();
    if(!mem_ebpf_skel) {
        ERRNO("Failed to open BPF skeleton");
        return -errno;
    }

    /* Load the BPF objectes */
    if (mem_ebpf__load(mem_ebpf_skel)) {
        ERRNO("Failed to load BPF object");
        return -errno;
    }

    /* ARM64 phys to virt translation requires two values, one of the two (CONFIG_ARM64_VA_BITS)
     * might not be available from config.gz so we try to compute it at runtime
     */
    #if defined(__TARGET_ARCH_arm64)
        key = 0;
        vabits = 39;
        kconfig_map = bpf_object__find_map_by_name(mem_ebpf_skel->obj, ".kconfig");
        if(!kconfig_map || \
           ((map_fd = bpf_map__fd(kconfig_map)) < 0) || \
           (bpf_map_lookup_elem(map_fd, &key, &cfg_vals))) {
            WARN("No .kconfig section in eBPF program");
            goto estimate;
        }

        ctx->va_bits_config = cfg_vals.CONFIG_ARM64_VA_BITS;
        DBG("CONFIG_ARM64_VA_BITS %lu", ctx->va_bits_config);
        if(ctx->va_bits_config)
            ctx->va_bits = ctx->va_bits_config;
        else {
            estimate:
                vabits = arm64_vabits_actual();
                if (vabits == 0) {
                    WARN("Failed to determine runtime virtual address bits, defaulting to 48");
                    vabits = 48;
                }
                DBG("Estimated va_bits %lu", vabits);
                ctx->va_bits = vabits;
        }
        DBG("va_bits %lu", ctx->va_bits);
    #endif

    /* Attach the uprobe to the 'read_kernel_memory' function in the current executable */
    bpf_prog_link = bpf_program__attach(mem_ebpf_skel->progs.read_kernel_memory_uprobe);
    if (bpf_prog_link && !ctx->opts.force_xdp) {
        ctx->ebpf_trigger = UPROBE;
    } 
    else {
        ctx->ebpf_trigger = XDP;
        fprintf(stderr, "Failed to attach eBPF Uprobe program, use XDP fallback...\n");
        
        /* Get loopback interface index by name "lo" (usually 1) */
        int ifindex = if_nametoindex(loopback_interface);
        if (ifindex <= 0) {
            ERRNO("Failed to get interface index");
            return -errno;
        }
        
        /* Attach XDP program to the interface */
        bpf_prog_link = bpf_program__attach_xdp(mem_ebpf_skel->progs.read_kernel_memory_xdp, ifindex);
        if (!bpf_prog_link) {
            ERR("Failed to attach XDP program to interface %s", loopback_interface);
            return -errno;
        }
        
        /* Create socket for sending trigger packets */
        if ((ret = init_udp_socket())) {
            return ret;
        }
    }
    // TODO: implment the BPF_PROG_TEST_RUN mode
    
    /* Create the mmap */
    if((ret = init_mmap())) {
        return ret;
    }

    INFO("eBPF program loaded");

    return 0;
}

/*
 * cleanup_mem_ebpf() - Unmaps the shared memory region used to access map and free eBPF resources.
 */
void cleanup_mem_ebpf() {
    if(mem_ebpf_skel) {
        if(read_mem_result) munmap(read_mem_result, sizeof(struct read_mem_result));
        mem_ebpf__destroy(mem_ebpf_skel);
    }

    /* Destroy bpf_link if it exists*/
    if (bpf_prog_link) {
        bpf_link__destroy(bpf_prog_link);
        bpf_prog_link = NULL;
    }

    /* Close UDP socket if it's open */
    if (udp_sockfd > 0) {
        close(udp_sockfd);
        udp_sockfd = -1;
    }

    INFO("eBPF program unloaded");
}

/*
 * phys_to_virt() - Convert a physical address to a virtual address using direct mapping
 * @phy_addr: Physical address to translate
 *
 * Performs architecture-specific translation using kernel direct mapping.
 * Currently supports x86_64 and ARM64 only.
 */
uintptr_t phys_to_virt(const struct lemon_ctx *restrict ctx, const uintptr_t phy_addr) {

    #ifdef __TARGET_ARCH_x86
        return phy_addr + ctx->v2p_offset;
    #elif __TARGET_ARCH_arm64
        return (phy_addr - ctx->v2p_offset) | (0xffffffffffffffff << ctx->va_bits);
    #else
        return phy_addr;
    #endif
}

/*
 * send_udp_trigger_packet() - Send UDP packets to trigger XDP program
 * @addr: Virtual address of the memory region to read
 * @size: Size of the memory region to read
 */
static int send_udp_trigger_packet(const uintptr_t addr, const size_t size) {
    ssize_t sent_bytes;
    struct sockaddr_in dest_addr;
    struct read_mem_args args;

    /* Setup memory read arguments in payload */
    args.addr = addr;
    args.size = size;

    /* Setup destination address (loopback) */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest_addr.sin_port = htons(9999);

    /* Send the UDP packet */
    sent_bytes = sendto(udp_sockfd, &args, sizeof(args), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent_bytes < 0) {
        ERRNO("Failed to send UDP trigger packet");
        return -errno;
    }

    /* Check partial send*/
    if (sent_bytes != sizeof(args)) {
        fprintf(stderr, "Incomplete packet send: %zd of %zu bytes\n", sent_bytes, sizeof(args));
        return -EIO;
    }

    return 0;
}

/*
 * read_kernel_memory() - Trigger eBPF UProbe or XDP to read kernel virtual memory
 * @addr: Virtual address of the memory region to read
 * @size: Size of the memory region to read
 * @data: Pointer to store the output data
 *
 * This function triggers an eBPF UProbe or XDP to read the specified memory region in kernel space.
 * The function is marked with `noinline` and `optnone` to ensure the code is not optimized or inlined by the compiler.
 */
int __attribute__((noinline, optnone)) read_kernel_memory(const uintptr_t addr, const size_t size, __u8 **restrict data) {
    // ctx->opts.simulate!
    /* If the Uprobe support is not active in kernel, use XDP to read the memory*/
    if(udp_sockfd > 0) {
        int ret;

        /* Send UDP trigger packet for XDP*/
        ret = send_udp_trigger_packet(addr, size);
        if (ret < 0) {
            read_mem_result->ret_code = ret;
            return ret;
        }
    }

    *data = read_mem_result->buf;
    return read_mem_result->ret_code;
}

/*
 * parse_kallsyms_line() - Extracts the address of a specific kernel symbol from a text line
 * @line: A line of text, typically from /proc/kallsyms or System.map
 * @symbol: The name of the symbol to search for
 * @symbol_addr: Pointer to store the resolved symbol address
 *
 * Scans the line for the symbol name and extracts its address using sscanf.
 * Returns 1 on success, 0 on not looked for element or a negative error code from read_kernel_memory().
 */
static int inline parse_kallsyms_line(const char *restrict line, const char *restrict symbol, uintptr_t *restrict current_symb_addr) {
    char current_symb_name[256];

    /* Read the address and check if the it is the symbol that we look for */
    if ((sscanf(line, "%lx %*c %255s\n", current_symb_addr, current_symb_name) != 2) || strncmp(current_symb_name, symbol, strlen(symbol)))
        return 0;

    /* Check that address is not 0 */
    return current_symb_addr != 0;
}

/*
 * parse_kallsyms() - Parse /proc/kallsyms extracting needed symbols
 *
 * Opens /proc/kallsyms, searches for the appropriate symbol (e.g., "page_offset_base" or 
 * "memstart_addr" and "iomem_resource") based on architecture, and retrieves the physical-to-virtual address 
 * translation offset and the pointer to the tree of physical memory regions. 
 * Returns 0 on success, or an error code on failure.
 */
static int parse_kallsyms(struct lemon_ctx *restrict ctx) {
    FILE *fp;
    char line[256];
    __u8 *data = NULL;
    uintptr_t current_symb_addr = 0;
    int err;

    /* Make sure we can use the same read for signed and unsigned offsets (arm/intel) */
    _Static_assert(sizeof(uintptr_t) == sizeof(int64_t), "sizeof(uintptr_t) != sizeof(int64_t)");

    /* Check for capabilities */
    if((check_capability(ctx, CAP_SYSLOG) <= 0)) {
        ERR("LEMON does not have CAP_SYSLOG to read addresses from /proc/kallsyms");
        return EPERM;
    }

    #ifdef __TARGET_ARCH_x86
        char *v2p_symbol = "page_offset_base";
    #elif __TARGET_ARCH_arm64
        char *v2p_symbol = "memstart_addr";
    #endif

    /* Open the kallsyms file and look for symbols in it*/
    fp = fopen("/proc/kallsyms", "r");
    if (!fp)
    {
        ERRNO("Failed to open /proc/kallsyms");
        return errno;
    }

    /* Look for all the symbols */
    while (fgets(line, sizeof(line), fp)) {

        /* Check if all the symbols are already found */
        if(ctx->iomem_resource && ctx->v2p_offset) break;

        /* Look for symbols */
        if(!ctx->iomem_resource && parse_kallsyms_line(line, "iomem_resource", &current_symb_addr)) {
            ctx->iomem_resource = current_symb_addr;
            DBG("iomem_resource 0x%lx", ctx->iomem_resource);
            continue;
        }

        if(!ctx->v2p_offset && parse_kallsyms_line(line, v2p_symbol, &current_symb_addr)) {

            /* Read it to obtain the offset */
            if((err = read_kernel_memory(current_symb_addr, sizeof(uintptr_t), &data))) break;
            #ifdef __TARGET_ARCH_x86
                ctx->v2p_offset = *((uintptr_t *)data);
            #elif __TARGET_ARCH_arm64
                ctx->v2p_offset = *((int64_t *)data);
            #endif

            DBG("v2p_offset 0x%lx", ctx->v2p_offset);
            continue;
        }
    }

    if(fclose(fp)) {
        ERRNO("Fail to close /proc/kallsyms");
        return errno;
    }

    /* Check if all the virtual to phisical offset is found */
    if (!ctx->v2p_offset)
    {
        ERR("Symbol %s not found in /proc/kallsyms", v2p_symbol);
        return EIO;
    }

    INFO("/proc/kallsyms symbols correctly parsed");

    return 0;
}

/*
 * toggle_kptr() - Toggle the kernel.kptr_restrict sysctl setting
 *
 * Reads and toggles /proc/sys/kernel/kptr_restrict between 0 and its original value (only if needed).
 * Caches the original value on first call. Returns 0 on success, or an error code on failure.
 */
 int toggle_kptr(struct lemon_ctx *restrict ctx) {

    struct stat stat_tmp;
    FILE *kptr_fd;
    int current_kptr_status, new_kptr_status, cap_ret, err = 0;

    /* If kptr_restrict does not exists (?) do nothing */
    if(stat("/proc/sys/kernel/kptr_restrict", &stat_tmp)) {
        WARN("/proc/sys/kernel/kptr_restrict not found");
        return 0;
    }

    /* Open the file */
    if(!(kptr_fd = fopen("/proc/sys/kernel/kptr_restrict", "r"))) {
        ERRNO("Failed to open /proc/sys/kernel/kptr_restrict");
        return errno;
    }
    
    /* Read current kptr_status */
    if(fscanf(kptr_fd, "%d", &current_kptr_status) == EOF) {
        ERRNO("Fail to read /proc/sys/kernel/kptr_restrict");
        err = errno;
        goto cleanup;
    }

    /* Save the original value */
    if(ctx->original_kptr == -1) {
        ctx->original_kptr = current_kptr_status;
    }

    /* If the original kptr_value is 0 do nothing */
    if(!ctx->original_kptr) goto cleanup;

    /* If the value is 1 and we have CAP_SYSLOG is not necessary to toggle it (neigter CAP_SYS_ADMIN!) :) */
    if((ctx->original_kptr == 1) && (check_capability(ctx, CAP_SYSLOG) > 0)) goto cleanup;

    /* Check CAP_SYS_ADMIN to modify kptr_restrict */
    if((cap_ret = check_capability(ctx, CAP_SYS_ADMIN)) <= 0) {
        fprintf(stderr, "LEMON does not have CAP_SYS_ADMIN to modify /proc/sys/kernel/kptr_restrict policy\n");
        err = cap_ret;
        goto cleanup;
    }

    /* Reopen the file in RW mode */
    if(!(kptr_fd = freopen(NULL, "r+", kptr_fd))) {
        ERRNO("Failed to open /proc/sys/kernel/kptr_restrict in RW mode");
        err = errno;
        goto cleanup;
    }

    /* Toggle the kptr_restrict value*/
    new_kptr_status = (current_kptr_status > 0) ? 0 : ctx->original_kptr;
    if(fprintf(kptr_fd, "%d", new_kptr_status) < 0) {
        err = EIO;
        goto cleanup;
    }

    INFO("kptr_restrict toggled");

    cleanup:
    if(kptr_fd) {
        if(fclose(kptr_fd)) {
            ERRNO("Fail to close /proc/sys/kernel/kptr_restrict");
            return errno;
        }
    }

    return err;
}

/*
 * init_translation() - Initialize phys-to-virt translation and extract System RAM regions
 * @ram_regions: Output pointer for storing valid memory regions
 *
 * Initializes the physical-to-virtual address mapping and retrieves System RAM virtual address ranges 
 * from kernel or /proc/iomem.
 * Returns 0 on success or an error code on failure.
 */
int init_translation(struct lemon_ctx *restrict ctx) {
    int err;

    /* Parse kallsyms looking for symbols needed to initialize translatation system */
    if((err = parse_kallsyms(ctx))) return err;

    /* Obtain the list of physical memory to be dumped */
    err = parse_iomem(ctx);

    return err;

}
