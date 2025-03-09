#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <sys/stat.h>

#include "lemon.h"
#include "lemon.ebpf.skel.h"

extern int get_memory_regions(struct ram_regions *restrict ram_regions, struct lemon_ebpf *restrict skel);
extern int dump_on_disk(const char *const restrict dump_file, const struct ram_regions *restrict ram_regions);

/*
 *  load_ebpf_progs() - load and attach eBPF programs
 *  @skel: eBPF skeleton
 * 
 */
int load_ebpf_progs(struct lemon_ebpf **restrict skel) {
    /* Open the BPF object file */
    if (!(*skel = lemon_ebpf__open()))
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return errno;
    }

    /* Load the BPF objectes */
    if ((lemon_ebpf__load(*skel)))
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", errno);
        return errno;
    }

    /* Attach the uprobe to the 'read_kernel_memory' function in the current executable */
    if (lemon_ebpf__attach(*skel))
    {
        fprintf(stderr, "Failed to attach program\n");
        return errno;
    }

    #ifdef DEBUG
        printf("BPF program attached\n");
    #endif

    return 0;
}

int main(int argc, char **argv)
{
    struct lemon_ebpf *skel = NULL;
    struct ram_regions ram_regions;
    int err;

    struct stat stat_tmp;

    /* Check if is running as root */
    if(getuid() != 0) {
        printf("Must be run as root\n");
        return 0;
    }

    /* Parameters */
    if(argc < 2) {
        printf("Usage: lemon <output file>\n");
        return 0;
    }

    /* Check for eBPF support */
    bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, NULL, NULL, 0, NULL);
	if(errno == ENOSYS) {
        printf("eBPF not supported by this kernel :( %d\n", errno);
        return 1;
    }

    /* Check for eBPF CORE support */
    if(stat("/sys/kernel/btf/vmlinux", &stat_tmp)) {
        printf("eBPF CORE not supported by this kernel.\n");
        return 1;
    }

    /* Load eBPF progs */
    if((err = load_ebpf_progs(&skel))) return err;
    
    /* Determine the memory dumpable regions */
    if((err = get_memory_regions(&ram_regions, skel))) goto cleanup;

    /* Dump the content of the memory on a file */
    if((err = dump_on_disk(argv[1], &ram_regions))) goto cleanup;
    
    
    /* Cleanup: close BPF object */
    cleanup:
        if(skel) lemon_ebpf__destroy(skel);

    return 0;
}
