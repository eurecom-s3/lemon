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
struct mem_range *range_new(unsigned long long start, unsigned long long end, bool virtual);

/*
 * mem.c - eBPF memory reader, kallsyms / kptr_restrict helpers, and phys-to-virt.
 *
 * Loads the mem eBPF skeleton, selects a trigger (uprobe, XDP, or BPF_PROG_TEST_RUN),
 * maps the result array to userspace, and exposes read_kernel_memory() for the rest
 * of LEMON.
 */

/* Loaded eBPF skeleton (programs, maps, links). */
static struct mem_ebpf *mem_ebpf_skel;

/* XDP path: UDP socket used to send trigger packets to loopback. */
static int udp_sockfd = -1;
static const char *loopback_interface = "lo";
/* Non-NULL when uprobe or XDP is attached; destroyed in cleanup_mem_ebpf(). */
static struct bpf_link *bpf_prog_link = NULL;

/* Which trigger path is active after load_ebpf_mem_progs(); xdp_prog_fd used for TEST_RUN. */
static enum ebpf_trigger active_trigger = TRIGGER_UNDEFINED;
static int xdp_prog_fd = -1;

/*
 * Synthetic Ethernet/IPv4/UDP packet used as BPF_PROG_TEST_RUN input.
 * The packet is pre-built by init_test_run_pkt() and only args.addr/size
 * are updated per call.  Must be packed to match the byte layout the XDP
 * program's header-parsing code expects.
 */
struct test_run_pkt {
    __u8  eth_dst[6];       /* Destination MAC (zeroed; loopback ignores it). */
    __u8  eth_src[6];       /* Source MAC (zeroed). */
    __u16 eth_proto;        /* 0x0800 (IPv4). */
    __u8  ip_vhl;           /* Version(4) + IHL(5) = 0x45. */
    __u8  ip_tos;
    __u16 ip_tot_len;       /* 20 (IP) + 8 (UDP) + sizeof(read_mem_args). */
    __u16 ip_id;
    __u16 ip_frag_off;
    __u8  ip_ttl;           /* 64. */
    __u8  ip_proto;         /* 17 (UDP). */
    __u16 ip_csum;          /* Zeroed; XDP program does not validate checksum. */
    __u32 ip_src;           /* 127.0.0.1 in network byte order. */
    __u32 ip_dst;           /* 127.0.0.1 in network byte order. */
    __u16 udp_sport;
    __u16 udp_dport;        /* 9999 (TRIGGER_PACKET_PORT). */
    __u16 udp_len;          /* 8 + sizeof(read_mem_args). */
    __u16 udp_csum;
    struct read_mem_args args; /* Address and size for the eBPF reader. */
} __attribute__((packed));

static struct test_run_pkt test_run_pkt;
static struct bpf_test_run_opts test_run_opts;

/* BPF_MAP_TYPE_ARRAY fd and mmap of read_mem_result (shared with kernel eBPF). */
static int read_mem_result_fd;
static struct read_mem_result *read_mem_result;

#if defined(__TARGET_ARCH_arm64)
    /*
     * is_mmap_respecting_address() - Probe whether the VA space uses a given top bit
     * @addr: Hint address (high bit of candidate VA_BITS minus one).
     *
     * mmap() without MAP_FIXED may place the mapping at or above the hint. If the
     * mapping lands at or above @addr, the kernel treats that virtual range as usable.
     * Used to infer CONFIG_ARM64_VA_BITS when kconfig is missing from the eBPF object.
     *
     * Returns true if the probe suggests the address range is valid, false otherwise.
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

        /* Success if the kernel honored the hint (mapped at or above the requested address). */
        if (mapped_addr >= addr) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * arm64_vabits_actual() - Guess ARM64 virtual address width at runtime
     *
     * Tries 48 vs 52 first, then 47, 42, 39, 36. Returns 0 if no probe matched.
     */
    static unsigned long arm64_vabits_actual() {
        unsigned long vabits = 0;

        /* 48-bit VA is the common case; distinguish 52-bit if both probes succeed. */
        if (is_mmap_respecting_address((void*)(1ul << (48 - 1)))) {
            if (is_mmap_respecting_address((void*)(1ul << (52 - 1)))) {
                vabits = 52;
            } else {
                vabits = 48;
            }
        } else {
            /* Less common VA sizes from Kconfig. */
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
#endif /* __TARGET_ARCH_arm64 */

/*
 * init_mmap() - Map the eBPF read_mem_array_map into userspace
 *
 * Obtains the map file descriptor and mmap(MAP_SHARED)s struct read_mem_result so
 * read_kernel_memory() and the eBPF programs share one buffer.
 *
 * Returns 0 on success, or a positive errno-style code on failure.
 */
static int init_mmap() {
    read_mem_result_fd = bpf_map__fd(mem_ebpf_skel->maps.read_mem_array_map);
    if(read_mem_result_fd < 0) {
        int saved = errno;
        if (saved)
            ERRNO("Failed to get BPF map fd");
        else
            ERR("Failed to get BPF map fd");
        return saved ? saved : ENOENT;
    }

    read_mem_result = (struct read_mem_result *)mmap(NULL, sizeof(struct read_mem_result), PROT_READ | PROT_WRITE, MAP_SHARED, read_mem_result_fd, 0);
    if (read_mem_result == MAP_FAILED) {
        RETURN_ERRNO("Failed to mmap BPF map");
    }

    return 0;
}


/*
 * init_udp_socket() - Create UDP socket for XDP trigger packets
 *
 * Used when XDP is attached; send_udp_trigger_packet() sends struct read_mem_args
 * to 127.0.0.1:9999 to drive read_kernel_memory_xdp.
 *
 * Returns 0 on success, or a positive errno-style code on failure.
 */
static int init_udp_socket() {
    /* DGRAM socket; destination is set per sendto() in send_udp_trigger_packet(). */
    udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        RETURN_ERRNO("Failed to create UDP socket for XDP trigger");
    }

    return 0;
}

/*
 * init_test_run_pkt() - Build synthetic Ethernet/IP/UDP packet for BPF_PROG_TEST_RUN
 *
 * Fills test_run_pkt and test_run_opts so bpf_prog_test_run_opts() can invoke the
 * same XDP program logic without a live interface.
 */
static void init_test_run_pkt(void) {
    memset(&test_run_pkt, 0, sizeof(test_run_pkt));
    /* IPv4 ethertype, minimal IPv4 + UDP header sizes and loopback endpoints. */
    test_run_pkt.eth_proto  = htons(0x0800);
    test_run_pkt.ip_vhl     = 0x45;
    test_run_pkt.ip_ttl     = 64;
    test_run_pkt.ip_proto   = 17;
    test_run_pkt.ip_src     = htonl(0x7f000001);
    test_run_pkt.ip_dst     = htonl(0x7f000001);
    test_run_pkt.ip_tot_len = htons(20 + 8 + sizeof(struct read_mem_args));
    test_run_pkt.udp_dport  = htons(9999);
    test_run_pkt.udp_len    = htons(8 + sizeof(struct read_mem_args));

    memset(&test_run_opts, 0, sizeof(test_run_opts));
    test_run_opts.sz           = sizeof(test_run_opts);
    test_run_opts.data_in      = &test_run_pkt;
    test_run_opts.data_size_in = sizeof(test_run_pkt);
}

/*
 * load_ebpf_mem_progs() - Open, load, attach eBPF memory reader and mmap the result map
 * @ctx: Runtime context (va_bits, sparsemem, trigger flags updated here).
 *
 * On ARM64, fills ctx->va_bits from .kconfig or arm64_vabits_actual().
 * Trigger order: forced TEST_RUN / XDP, else uprobe, else XDP+UDP, else TEST_RUN.
 *
 * Returns 0 on success, or a positive errno-style code on failure.
 */
int load_ebpf_mem_progs(struct lemon_ctx *restrict ctx) {
    int ret;

    #if defined(__TARGET_ARCH_arm64)
        unsigned long vabits = 0;
    #endif

    /* libbpf may raise RLIMIT_MEMLOCK; warn if neither CAP_PERFMON nor CAP_SYS_ADMIN. */
    if((check_capability(ctx, CAP_PERFMON) != 1) && (check_capability(ctx, CAP_SYS_ADMIN) != 1)) {
        WARN("LEMON does not have CAP_PERFMON needed to modify RLIMIT_MEMLOCK");
    }

    mem_ebpf_skel = mem_ebpf__open();
    if(!mem_ebpf_skel) {
        RETURN_ERRNO("Failed to open BPF skeleton");
    }

    if (mem_ebpf__load(mem_ebpf_skel)) {
        RETURN_ERRNO("Failed to load BPF object");
    }

    /* ARM64 phys to virt translation requires two values, one of the two (CONFIG_ARM64_VA_BITS)
     * might not be available from config.gz so we try to compute it at runtime
     */
    #if defined(__TARGET_ARCH_arm64)
        ctx->sparsemem_vmap_config = mem_ebpf_skel->kconfig->CONFIG_SPARSEMEM_VMEMMAP;
        DBG("CONFIG_SPARSEMEM_VMEMMAP %c", ctx->sparsemem_vmap_config);
        ctx->va_bits_config = mem_ebpf_skel->kconfig->CONFIG_ARM64_VA_BITS;
        DBG("CONFIG_ARM64_VA_BITS %lu", ctx->va_bits_config);
        if(ctx->va_bits_config)
            ctx->va_bits = ctx->va_bits_config;
        else {
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

    /* Trigger selection (unless -t / -x force a path): uprobe, then XDP, then TEST_RUN. */
    if (ctx->opts.force_test_run)
        goto try_test_run;

    if (ctx->opts.force_xdp)
        goto try_xdp;

    bpf_prog_link = bpf_program__attach(mem_ebpf_skel->progs.read_kernel_memory_uprobe);
    if (bpf_prog_link && !libbpf_get_error(bpf_prog_link)) {
        ctx->ebpf_trigger = UPROBE;
        active_trigger = UPROBE;
        goto trigger_done;
    }
    bpf_prog_link = NULL;

try_xdp:;
    int ifindex = if_nametoindex(loopback_interface);
    if (ifindex <= 0) {
        WARN("Failed to get loopback interface index, falling back to PROG_TEST_RUN");
        goto try_test_run;
    }

    bpf_prog_link = bpf_program__attach_xdp(mem_ebpf_skel->progs.read_kernel_memory_xdp, ifindex);
    if (!bpf_prog_link || libbpf_get_error(bpf_prog_link)) {
        WARN("Failed to attach XDP program, falling back to PROG_TEST_RUN");
        bpf_prog_link = NULL;
        goto try_test_run;
    }

    if ((ret = init_udp_socket())) {
        WARN("Failed to create UDP socket, falling back to PROG_TEST_RUN");
        bpf_link__destroy(bpf_prog_link);
        bpf_prog_link = NULL;
        goto try_test_run;
    }

    ctx->ebpf_trigger = XDP;
    active_trigger = XDP;
    INFO("Dump using XDP as eBPF trigger");
    goto trigger_done;

try_test_run:
    xdp_prog_fd = bpf_program__fd(mem_ebpf_skel->progs.read_kernel_memory_xdp);
    if (xdp_prog_fd < 0) {
        int saved = errno;
        ERR("Failed to get XDP program fd for PROG_TEST_RUN");
        return saved ? saved : ENOENT;
    }
    init_test_run_pkt();
    ctx->ebpf_trigger = PROG_TEST_RUN;
    active_trigger = PROG_TEST_RUN;
    INFO("Dump using BPF_PROG_TEST_RUN as eBPF trigger");

trigger_done:
    if((ret = init_mmap())) {
        return ret;
    }

    INFO("eBPF program loaded");

    return 0;
}

/*
 * cleanup_mem_ebpf() - munmap result buffer, destroy skeleton, link, and UDP socket
 *
 * Safe to call multiple times; clears module state used by the memory reader.
 */
void cleanup_mem_ebpf() {
    if(mem_ebpf_skel) {
        if(read_mem_result && read_mem_result != MAP_FAILED)
            munmap(read_mem_result, sizeof(struct read_mem_result));
        mem_ebpf__destroy(mem_ebpf_skel);
    }

    if (bpf_prog_link) {
        bpf_link__destroy(bpf_prog_link);
        bpf_prog_link = NULL;
    }

    if (udp_sockfd >= 0) {
        close(udp_sockfd);
        udp_sockfd = -1;
    }

    INFO("eBPF program unloaded");
}

/*
 * phys_to_virt() - Map a physical frame to a kernel direct-map virtual address
 * @ctx: Holds v2p_offset and (arm64) va_bits.
 * @phy_addr: Physical address (page-aligned in practice).
 *
 * x86_64: linear map offset. arm64: subtract memstart_addr and sign-extend using va_bits.
 * Other arches: identity mapping.
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
 * send_udp_trigger_packet() - Send a UDP payload to fire the XDP reader
 * @addr: Kernel virtual address to read (passed in read_mem_args).
 * @size: Number of bytes to read (passed in read_mem_args).
 *
 * Destination is 127.0.0.1:9999; XDP program parses read_mem_args from the UDP payload.
 * Returns 0 on success, EIO on short write, or errno from sendto().
 */
static int send_udp_trigger_packet(const uintptr_t addr, const size_t size) {
    static struct sockaddr_in dest_addr;
    static bool initialized = false;
    struct read_mem_args args;

    /* One-time sockaddr setup (hot path: called once per page). */
    if (!initialized) {
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_addr.s_addr = htonl(0x7f000001);
        dest_addr.sin_port = htons(9999);
        initialized = true;
    }

    args.addr = addr;
    args.size = size;

    ssize_t sent_bytes = sendto(udp_sockfd, &args, sizeof(args), 0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        RETURN_ERRNO("Failed to send UDP trigger packet");
    }
    if (sent_bytes != sizeof(args)) {
        ERR("Incomplete packet send: %zd of %zu bytes", sent_bytes, sizeof(args));
        return EIO;
    }
    return 0;
}

/*
 * send_test_run_packet() - Run the XDP program via bpf_prog_test_run_opts()
 * @addr: Kernel virtual address to read.
 * @size: Number of bytes to read.
 *
 * Expects XDP_DROP when the program handled the synthetic packet.
 * Returns 0 on success, EIO if retval is not XDP_DROP, or errno from libbpf.
 */
static int send_test_run_packet(const uintptr_t addr, const size_t size) {
    test_run_pkt.args.addr = addr;
    test_run_pkt.args.size = size;

    if (bpf_prog_test_run_opts(xdp_prog_fd, &test_run_opts)) {
        RETURN_ERRNO("BPF_PROG_TEST_RUN failed");
    }

    if (test_run_opts.retval != XDP_DROP) {
        ERR("BPF_PROG_TEST_RUN: XDP program did not process packet (retval=%u)", test_run_opts.retval);
        return EIO;
    }

    return 0;
}

/*
 * _read_kernel_memory() - Entry point probed by uprobe; triggers XDP/TEST_RUN otherwise
 * @addr: Kernel virtual address to read.
 * @size: Number of bytes to read.
 * @data: Out: always set to read_mem_result->buf (even on trigger failure).
 *
 * For UPROBE, the eBPF program runs on function entry before this body executes.
 * Marked noinline/optnone so the uprobe attachment target remains stable.
 * Returns read_mem_result->ret_code (may be negative from the eBPF helper).
 */
static int __attribute__((noinline, optnone)) _read_kernel_memory(const uintptr_t addr, const size_t size, __u8 **restrict data) {
    if (active_trigger == XDP) {
        int ret = send_udp_trigger_packet(addr, size);
        if (ret) { read_mem_result->ret_code = ret; goto out; }
    } else if (active_trigger == PROG_TEST_RUN) {
        int ret = send_test_run_packet(addr, size);
        if (ret) { read_mem_result->ret_code = ret; goto out; }
    }
    /* UPROBE: eBPF already ran at entry; ret_code was set in-kernel. */

out:
    *data = read_mem_result->buf;
    return read_mem_result->ret_code;
}

/*
 * read_kernel_memory() - Public wrapper: reset ret_code, call _read_kernel_memory, normalize sign
 * @addr: Kernel virtual address to read.
 * @size: Number of bytes to read.
 * @data: Out: pointer to mmap-backed buffer filled by eBPF.
 *
 * Negative kernel codes are returned as positive errno-style values for callers.
 */
 int read_kernel_memory(const uintptr_t addr, const size_t size, __u8 **restrict data) {
    /* Default if the map was never attached correctly. */
    read_mem_result->ret_code = -EINVAL;

    int rc = _read_kernel_memory(addr, size, data);
    return rc < 0 ? -rc : rc;
 }

/*
 * parse_kallsyms_line() - Parse one /proc/kallsyms line for a given symbol name
 * @line: Line buffer (kallsyms format: address type name).
 * @symbol: Symbol name to match (e.g. "iomem_resource").
 * @current_symb_addr: Out: parsed address when the name matches.
 *
 * Returns 1 if @symbol was found and the address is non-zero; 0 otherwise.
 */
static inline int parse_kallsyms_line(const char *restrict line, const char *restrict symbol, uintptr_t *restrict current_symb_addr) {
    char current_symb_name[256];

    /* Parse address and name; ignore lines that do not match @symbol. */
    if ((sscanf(line, "%lx %*c %255s\n", current_symb_addr, current_symb_name) != 2) || strcmp(current_symb_name, symbol)) {
        return 0;
    }

    return *current_symb_addr != 0;
}

/*
 * parse_kallsyms() - Load iomem_resource, v2p offset, and mem_section from /proc/kallsyms
 * @ctx: Context; sets iomem_resource, v2p_offset (x86/arm64), mem_section.
 *
 * Requires CAP_SYSLOG. Reads the live value of page_offset_base / memstart_addr via
 * read_kernel_memory() for phys-to-virt. Stops scanning once all needed symbols are set.
 *
 * Returns 0 on success, or an error code on failure.
 */
static int parse_kallsyms(struct lemon_ctx *restrict ctx) {
    FILE *fp;
    char line[256];
    __u8 *data = NULL;
    uintptr_t current_symb_addr = 0;
    int err;
    size_t linux_banner_len;

    /* uintptr_t and int64_t must match for mixed x86/arm offset reads. */
    _Static_assert(sizeof(uintptr_t) == sizeof(int64_t), "sizeof(uintptr_t) != sizeof(int64_t)");

    /* Unmasked kallsyms addresses require CAP_SYSLOG (or similar). */
    if((check_capability(ctx, CAP_SYSLOG) != 1)) {
        ERR("LEMON does not have CAP_SYSLOG to read addresses from /proc/kallsyms");
        return EPERM;
    }

    #ifdef __TARGET_ARCH_x86
        const char *v2p_symbol = "page_offset_base";
    #elif __TARGET_ARCH_arm64
        const char *v2p_symbol = "memstart_addr";
    #endif

    fp = fopen("/proc/kallsyms", "r");
    if (!fp)
    {
        RETURN_ERRNO("Failed to open /proc/kallsyms");
    }

    while (fgets(line, sizeof(line), fp)) {

        /* Early exit once iomem root, phys offset, and mem_section are known. */
        if(ctx->iomem_resource && ctx->v2p_offset && ctx->mem_section && ctx->linux_banner) break;

        /* Root of kernel struct resource tree (optional path for RAM discovery). */
        if(!ctx->iomem_resource && parse_kallsyms_line(line, "iomem_resource", &current_symb_addr)) {
            ctx->iomem_resource = current_symb_addr;
            DBG("iomem_resource 0x%lx", ctx->iomem_resource);
            continue;
        }

        if(!ctx->v2p_offset && parse_kallsyms_line(line, v2p_symbol, &current_symb_addr)) {

            /* Dereference the kernel symbol to get page_offset_base / memstart_addr. */
            if((err = read_kernel_memory(current_symb_addr, sizeof(uintptr_t), &data))) {
                fclose(fp);
                return err;
            }
            #ifdef __TARGET_ARCH_x86
                ctx->v2p_offset = *((uintptr_t *)data);
            #elif __TARGET_ARCH_arm64
                ctx->v2p_offset = *((int64_t *)data);
            #endif

            DBG("v2p_offset 0x%lx", ctx->v2p_offset);
            continue;
        }
        
        /* Address of mem_section array needed to find struct page array (vmemmap) for Qualcomm quirks */
        if(!ctx->mem_section && parse_kallsyms_line(line, "mem_section", &current_symb_addr)) {
            ctx->mem_section = current_symb_addr;
            DBG("mem_section 0x%lx", ctx->mem_section);
            continue;
        }

        /* Get the Linux banner string */
        if(!ctx->linux_banner && parse_kallsyms_line(line, "linux_banner", &current_symb_addr)) {
            if((err = read_kernel_memory(current_symb_addr, MAX_LINUX_BANNER_LEN, &data))) {
                fclose(fp);
                return err;
            }
            
            /* Banner ends with  new line, we replace it with a NULL */
            char *newline = strchr((char *)data, '\n');
            if(newline) *newline = '\0';

            linux_banner_len = strnlen((char *)data, MAX_LINUX_BANNER_LEN);
            if(!linux_banner_len) {
                ERR("Linux banner has 0 len");
                fclose(fp);
                return EINVAL;
            }

            ctx->linux_banner = (char *)malloc(linux_banner_len + 1);
            if(!ctx->linux_banner) {
                ERR("Fail allocating Linux banner buffer");
                fclose(fp);
                return errno;
            }

            strncpy(ctx->linux_banner, (char *)data, linux_banner_len);
            
            DBG("Linux banner 0x%s", ctx->linux_banner);
            continue;
        }

    }

    if(fclose(fp)) {
        RETURN_ERRNO("Fail to close /proc/kallsyms");
    }

    /* v2p_offset is mandatory for phys_to_virt(). */
    if (!ctx->v2p_offset)
    {
        ERR("Symbol %s not found in /proc/kallsyms", v2p_symbol);
        return EIO;
    }

    INFO("/proc/kallsyms symbols correctly parsed");

    return 0;
}

/*
 * toggle_kptr() - Lower kernel.kptr_restrict when needed so kallsyms addresses are usable
 * @ctx: Caches ctx->original_kptr on first call; restores on a second call with toggled value.
 *
 * If the original value is 0, or is 1 with CAP_SYSLOG, no write is performed.
 * Otherwise requires CAP_SYS_ADMIN to write 0 while dumping; restore uses saved original.
 *
 * Returns 0 on success, or an error code on failure.
 */
 int toggle_kptr(struct lemon_ctx *restrict ctx) {

    struct stat stat_tmp;
    FILE *kptr_fd;
    int current_kptr_status, new_kptr_status, cap_ret, err = 0;

    /* Optional sysctl on some kernels. */
    if(stat("/proc/sys/kernel/kptr_restrict", &stat_tmp)) {
        WARN("/proc/sys/kernel/kptr_restrict not found");
        return 0;
    }

    if(!(kptr_fd = fopen("/proc/sys/kernel/kptr_restrict", "r"))) {
        RETURN_ERRNO("Failed to open /proc/sys/kernel/kptr_restrict");
    }

    if(fscanf(kptr_fd, "%d", &current_kptr_status) != 1) {
        err = errno;
        ERRNO("Fail to read /proc/sys/kernel/kptr_restrict");
        goto cleanup;
    }

    if(ctx->original_kptr == -1) {
        ctx->original_kptr = current_kptr_status;
    }

    /* Already unrestricted at boot. */
    if(!ctx->original_kptr) goto cleanup;

    /* kptr_restrict==1 still exposes symbols to CAP_SYSLOG readers. */
    if((ctx->original_kptr == 1) && (check_capability(ctx, CAP_SYSLOG) == 1)) goto cleanup;

    /* Need CAP_SYS_ADMIN to relax kptr_restrict from 2 (typical) to 0. */
    if((cap_ret = check_capability(ctx, CAP_SYS_ADMIN)) != 1) {
        ERR("LEMON does not have CAP_SYS_ADMIN to modify /proc/sys/kernel/kptr_restrict policy");
        err = (cap_ret > 1) ? cap_ret : EPERM;
        goto cleanup;
    }

    /* Same FILE*, reopened read-write (Linux /proc allows this). */
    if(!(kptr_fd = freopen(NULL, "r+", kptr_fd))) {
        err = errno;
        ERRNO("Failed to open /proc/sys/kernel/kptr_restrict in RW mode");
        goto cleanup;
    }

    /* If currently restricted, open addresses; else restore boot value. */
    new_kptr_status = (current_kptr_status > 0) ? 0 : ctx->original_kptr;
    if(fprintf(kptr_fd, "%d", new_kptr_status) < 0) {
        err = EIO;
        goto cleanup;
    }

    INFO("kptr_restrict toggled");

    cleanup:
    /* Preserve first error if fclose also fails. */
    if(kptr_fd) {
        if(fclose(kptr_fd)) {
            if (!err) err = errno;
            ERRNO("Fail to close /proc/sys/kernel/kptr_restrict");
        }
    }

    return err;
}

/*
 * init_translation() - Resolve kallsyms, then build ctx->ram_regions
 * @ctx: Filled with v2p data and either forced range or parse_iomem() output.
 *
 * Returns 0 on success or an error code on failure.
 */
int init_translation(struct lemon_ctx *restrict ctx) {
    int err;
    struct mem_range *n;

    if((err = parse_kallsyms(ctx))) return err;

    /* User-supplied range (-r / -v) bypasses automatic RAM discovery. */
    if(ctx->opts.force_dump_range) {
        n = range_new(ctx->opts.forced_range.start, ctx->opts.forced_range.end, ctx->opts.forced_range.virtual);
        if (!n) {
            ERR("Failed to allocate forced memory range (start=0x%llx end=0x%llx)",
                ctx->opts.forced_range.start, ctx->opts.forced_range.end);
            return ENOMEM;
        }
        TAILQ_INSERT_TAIL(&ctx->ram_regions, n, entries);
    }
    else {
        /* Discover System RAM from kernel struct resource or /proc/iomem. */
        err = parse_iomem(ctx);
    }

    return err;

}
