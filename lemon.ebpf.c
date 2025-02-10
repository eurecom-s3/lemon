#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "lemon.h"

#define EINVAL 22

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct ebpf_buf);
    __uint(max_entries, 1);
} ram_memory SEC(".maps");

SEC("uprobe//proc/self/exe:read_kernel_memory")
int read_kernel_memory_uprobe(struct pt_regs *ctx)
{
    u64 address = (u64)(PT_REGS_PARM1_CORE(ctx));
    u64 dump_size = (u64)(PT_REGS_PARM2_CORE(ctx));
    
    int key = 0;
    struct ebpf_buf *ebpf_buf = bpf_map_lookup_elem(&ram_memory, &key);
    if (!ebpf_buf) {
        return -1; // We cannot catch this error...
    }

    // Ensure parameters are sanitized (some checks are needed to bypass eBPF type checking)
    #ifdef __TARGET_ARCH_x86
        if (address < 0 || address < 0xffff800000000000){
    #elif __TARGET_ARCH_arm64
        if (address < 0 || address < 0xffff000000000000){
    #else
        if(1){
    #endif
    
        ebpf_buf->ret_code = -EINVAL;
        return 0;
    }

    if (dump_size < 0 || dump_size > HUGE_PAGE_SIZE) {
        ebpf_buf->ret_code = -EINVAL;
        return 0;
    }

    // Read the kernel memory
    bpf_core_read((void *)(&ebpf_buf->buf), (u32)dump_size, (void *)address);
    ebpf_buf->ret_code = 0;

    return 0;
}

char _license[] SEC("license") = "GPL";