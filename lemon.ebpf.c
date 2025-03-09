#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

#include "lemon.h"

/* Mapping used to pass the memory content to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct read_mem_result);
    __uint(max_entries, 1);
} read_mem_array_map SEC(".maps");

/* UProbe called at the entry of read_kernel_memory */
SEC("uprobe//proc/self/exe:read_kernel_memory")
int read_kernel_memory_uprobe(struct pt_regs *ctx)
{
    /* Extract the first two arguments of the function */
    u64 address = (u64)(PT_REGS_PARM1_CORE(ctx));
    u64 dump_size = (u64)(PT_REGS_PARM2_CORE(ctx));
    
    /* Get the map in which save the memory content to pass to userspace */
    int key = 0;
    struct read_mem_result *read_mem_result = bpf_map_lookup_elem(&read_mem_array_map, &key);
    if (!read_mem_result) {
        return -1; // We cannot catch this error...
    }

    /* Ensure parameters are sanitized (some checks are needed to bypass eBPF type checking) */
    #ifdef __TARGET_ARCH_x86
        if (address < 0 || address < 0xffff800000000000){
    #elif __TARGET_ARCH_arm64
        if (address < 0 || address < 0xffff000000000000){
    #else
        if(1){
    #endif
    
        read_mem_result->ret_code = -EINVAL;
        return 0;
    }

    if (dump_size < 0 || dump_size > HUGE_PAGE_SIZE) {
        read_mem_result->ret_code = -EINVAL;
        return 0;
    }

    /* Read the kernel memory */
    bpf_core_read((void *)(&read_mem_result->buf), (u32)dump_size, (void *)address);
    read_mem_result->ret_code = 0;

    return 0;
}

char _license[] SEC("license") = "GPL";