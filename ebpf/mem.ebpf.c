/*
 * mem.ebpf.c - eBPF programs: uprobe and XDP triggers, mmapable result map.
 *
 * read_memory() validates and copies kernel bytes into read_mem_array_map for userspace.
 */

#ifdef CORE
    #include "../vmlinux.h"
    #include <bpf/bpf_core_read.h>

    #ifndef ETH_P_IP
        #define ETH_P_IP 0x0800
    #endif

    #ifndef IPPROTO_UDP
        #define IPPROTO_UDP 17
    #endif

#elif NOCORE
    #include <linux/bpf.h>
    #include <asm/ptrace.h>
    #include <linux/if_ether.h>
    #include <linux/in.h>
    #include <linux/ip.h>
    #include <linux/udp.h>

#elif NOCOREUNI
    #include "../nocore_universal.h"
    #include <bpf/bpf_tracing.h>
    
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#include "mem.ebpf.h"

/* Mapping used to pass the memory content to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct read_mem_result);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_MMAPABLE);
} read_mem_array_map SEC(".maps");

extern unsigned long CONFIG_ARM64_VA_BITS __kconfig __weak; /* VA bits for ARM64 */
extern char CONFIG_SPARSEMEM_VMEMMAP __kconfig __weak; /* Sparsemem VMEMMAP array configuration  */
__attribute__((used)) static void __keep_config_syms(void) {  /* WORKAROUND for LLVM */
    asm volatile("" : : "m"(CONFIG_ARM64_VA_BITS) : "memory");
    asm volatile("" : : "m"(CONFIG_SPARSEMEM_VMEMMAP) : "memory"); 
}

/*
 * read_memory() - Copy kernel bytes at @address into the mmapable BPF array map
 * @address: Kernel virtual address to read.
 * @dump_size: Number of bytes (clamped to HUGE_PAGE_SIZE in userspace policy).
 *
 * On validation failure sets read_mem_result->ret_code to -EINVAL and returns 0.
 * Returns -1 only if bpf_map_lookup_elem fails; otherwise 0 (probe return value).
 */
static inline int read_memory(__u64 address, const __u64 dump_size) {
    int key = 0;
    struct read_mem_result *read_mem_result = bpf_map_lookup_elem(&read_mem_array_map, &key);
    if (!read_mem_result) {
        return -1;
    }

    /* dump_size is __u64; upper bound matches userspace granule. */
    if (dump_size > HUGE_PAGE_SIZE) {
        read_mem_result->ret_code = -EINVAL;
        return 0;
    }

    /* Reject addresses that cannot be kernel pointers (unsigned compares on __u64). */
    #ifdef __TARGET_ARCH_x86
        if (address < 0xff00000000000000ULL){
    #elif __TARGET_ARCH_arm64
        if (address < 0xfff0000000000000ULL){
    #else
        /* Unknown arch for this build: reject all addresses (legacy behavior). */
        if (1){
    #endif
        read_mem_result->ret_code = -EINVAL;
        return 0;
    }

    /* Read the kernel memory */
    #ifdef CORE
        read_mem_result->ret_code = bpf_core_read((void *)(&read_mem_result->buf), (__u32)dump_size, (void *)address);
    #else
        read_mem_result->ret_code = bpf_probe_read_kernel((void *)(&read_mem_result->buf), (__u32)dump_size, (void *)address);
    #endif

    return 0;
}

/*
 * read_kernel_memory_uprobe() - Uprobe on userspace _read_kernel_memory()
 * @ctx: pt_regs at uprobed entry (arguments are address, size).
 *
 * Pulls PARM1/PARM2 as the kernel VA and length, then read_memory().
 */
SEC("uprobe//proc/self/exe:_read_kernel_memory")
int read_kernel_memory_uprobe(struct pt_regs *ctx)
{
    /* Match the x86_64/arm64 argument passing convention for the stub. */
    #ifdef CORE
        __u64 address = (__u64)(PT_REGS_PARM1_CORE(ctx));
        __u64 dump_size = (__u64)(PT_REGS_PARM2_CORE(ctx));
    #else
        __u64 address = (__u64)(PT_REGS_PARM1(ctx));
        __u64 dump_size = (__u64)(PT_REGS_PARM2(ctx));
    #endif

    return read_memory(address, dump_size);
}

#define TRIGGER_PACKET_PORT 9999
#define TRIGGER_PACKET_ADDR 0x7f000001 /* 127.0.0.1 */

/*
 * read_kernel_memory_xdp() - XDP program to trigger a kernel memory read
 * @ctx: Pointer to the XDP context containing packet metadata
 *
 * Parses a UDP packet containing address and size parameters used to
 * perform a kernel memory read. Expects UDP packets to 127.0.0.1:9999.
 */
SEC("xdp")
int read_kernel_memory_xdp(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    /* Validate Ethernet header */
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    /* Check if this is an IP packet */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* Validate and parse IP header */
    struct iphdr *ip = (struct iphdr*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    /* Validate IP header length */
    if (ip->ihl < 5) {
        return XDP_DROP;
    }
    
    /* Check if this is a UDP packet */
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    /* Validate UDP header */
    struct udphdr *udp = (struct udphdr*)((char*)ip + (ip->ihl * 4));
    if ((void*)(udp + 1) > data_end) {
        return XDP_DROP;
    }

    /* Check if source/dest is loopback */
    if (ip->saddr != bpf_htonl(TRIGGER_PACKET_ADDR) ||  ip->daddr != bpf_htonl(TRIGGER_PACKET_ADDR)) {
        return XDP_PASS;
    }

    /* Check destination port */
    if (udp->dest != bpf_htons(TRIGGER_PACKET_PORT)) {
        return XDP_PASS;
    }

    /* Validate payload */
    struct read_mem_args *args = (struct read_mem_args*)(udp + 1);
    if ((void*)(args + 1) > data_end) {
        return XDP_DROP;
    }

    __u64 address = args->addr;
    __u64 dump_size = args->size;

    if (read_memory(address, dump_size)) {
        return XDP_DROP;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
