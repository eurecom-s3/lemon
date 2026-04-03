#ifndef MEM_EBPF_H
#define MEM_EBPF_H

#include <errno.h>

#define PAGE_SIZE               4096
#define HUGE_PAGE_SIZE          (2 * 1024 * 1024)

struct read_mem_result {
    int ret_code;
    unsigned char buf[HUGE_PAGE_SIZE];
};

struct read_mem_args {
    unsigned long long addr; 
    unsigned long size;
};

#endif /* MEM_EBPF_H */
