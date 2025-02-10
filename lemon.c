#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#include "lemon.h"
#include "lemon.ebpf.skel.h"

lime_header header;
struct ebpf_buf ebpf_buf;
uintptr_t phy_to_virt_offset;

// Function to translate physical to virtual addresses
uintptr_t phys_to_virt(const uintptr_t phy_addr) {
    #ifdef __TARGET_ARCH_x86
        return phy_to_virt_offset + phy_addr;
    #elif __TARGET_ARCH_arm64
        return (phy_addr - phy_to_virt_offset) | 0xffff000000000000;
    #else
        return phy_addr;
    #endif
}

// Function to write the LiME header to a file
int write_lime_header_to_file(FILE *const restrict file, const uintptr_t start, const size_t end) {
    
    header.s_addr = start;
    header.e_addr = end;

    // Write the header to the file
    if (fwrite(&header, sizeof(lime_header), 1, file) != 1) {
        fprintf(stderr, "Error writing LiME header to file\n");
        return EIO;
    }

    return 0;
}

// Function hooked by UPROBE that trigger the eBPF program
void __attribute__((noinline, optnone)) read_kernel_memory(const uintptr_t addr, const size_t size)
{
    #ifdef DEBUG
        printf("Fetching memory from address: 0x%lx (Size 0x%zx)\n", addr, size);
    #endif
}

// Function to get the page_offset_base address from /proc/kallsyms
int get_phys_to_virt_offset(struct bpf_map *restrict map)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp)
    {
        perror("Failed to open /proc/kallsyms");
        return errno;
    }

    // Look for page_offset_base line 
    char line[256];
    uintptr_t kallsyms_symb_addr = 0;

    #ifdef __TARGET_ARCH_x86
        char *symbol = "page_offset_base";
    #elif __TARGET_ARCH_arm64
        char *symbol = "memstart_addr";
    #endif

    while (fgets(line, sizeof(line), fp))
        if (strstr(line, symbol) && (sscanf(line, "%lx", &kallsyms_symb_addr) == 1))  break;
    fclose(fp);

    if (!kallsyms_symb_addr)
    {
        fprintf(stderr, "%s not found in /proc/kallsyms\n", symbol);
        return EINVAL;
    }

    #ifdef DEBUG
        printf("%s at 0x%lx\n", symbol, kallsyms_symb_addr);
    #endif

    // Read the content of the kernel variable page_offset_base to get the offset of direct mapping region
    read_kernel_memory(kallsyms_symb_addr, sizeof(uintptr_t));

    int key = 0;
    if (bpf_map__lookup_elem(map, &key, sizeof(int), &ebpf_buf, sizeof(struct ebpf_buf), 0))
    {
        fprintf(stderr, "Failed to read map: %d\n", errno);
        return errno;
    }

    if(ebpf_buf.ret_code) {
        fprintf(stderr, "Error reading kernel memory at address 0x%lx, size: %zu\n", kallsyms_symb_addr, sizeof(uintptr_t));
        return ebpf_buf.ret_code;
    }
    
    phy_to_virt_offset = *((uintptr_t *)ebpf_buf.buf);

    #ifdef DEBUG
        printf("%s: 0x%lx\n", symbol, phy_to_virt_offset);
    #endif

    return 0;
}

// Function to read and store System RAM address ranges from /proc/iomem
int store_system_ram_range(struct ram_range **restrict const ranges, size_t *restrict const range_count)
{
    FILE *fp = fopen("/proc/iomem", "r");
    if (!fp)
    {
        perror("Failed to open /proc/iomem");
        return errno;
    }

    char line[256];
    int range_capacity = 10; // Initial capacity for storing ranges
    *range_count = 0;

    // Allocate initial memory
    *ranges = (struct ram_range *)malloc(range_capacity * sizeof(struct ram_range));
    if (!*ranges)
    {
        perror("Failed to allocate memory for RAM ranges");
        fclose(fp);
        return errno;
    }

    uintptr_t start, end;
    // Read each line and look for "System RAM"
    while (fgets(line, sizeof(line), fp))
    {
        if (strstr(line, "System RAM") && sscanf(line, "%lx-%lx", &start, &end) == 2)
        {
            // If the array is full, reallocate to increase its size
            if (*range_count >= range_capacity)
            {
                range_capacity *= 2;
                *ranges = (struct ram_range *)realloc(*ranges, range_capacity * sizeof(struct ram_range));
                if (!*ranges)
                {
                    perror("Failed to reallocate memory for RAM ranges");
                    fclose(fp);
                    return errno;
                }
            }

            // Store the range in the array
            (*ranges)[*range_count].start = start;
            (*ranges)[*range_count].end = end;
            (*range_count)++;
            
        }
    }
    fclose(fp);

    return 0;
}

int load_ebpf_prog(struct lemon_ebpf **restrict skel, struct bpf_map **restrict map) {
    // Open the BPF object file
    if (!(*skel = lemon_ebpf__open()))
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return errno;
    }

    // Load the BPF object
    if ((lemon_ebpf__load(*skel)))
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", errno);
        return errno;
    }

    // Attach the uprobe to the 'read_kernel_memory' function in the current executable
    if (lemon_ebpf__attach(*skel))
    {
        fprintf(stderr, "Failed to attach program\n");
        return errno;
    }

    #ifdef DEBUG
        printf("BPF program attached\n");
    #endif

    *map = (*skel)->maps.ram_memory; 

    return 0;
}

int main(int argc, char **argv)
{
    // eBPF objects
    struct lemon_ebpf *skel = NULL;
    struct bpf_map *map = NULL;

    int err;

    FILE *file = NULL;
    struct ram_range *ranges = NULL;
    size_t range_count = 0;
    struct stat stat_tmp;

    // Check if is running as root
    if(getuid() != 0) {
        printf("Must be run as root\n");
        return 0;
    }

    // Parameters
    if(argc < 2) {
        printf("Usage: lemon <output file>\n");
        return 0;
    }

    // Check for eBPF support
    bpf_prog_load(BPF_PROG_TYPE_UNSPEC, NULL, NULL, NULL, 0, NULL);
	if(errno == ENOSYS) {
        printf("eBPF not supported by this kernel :( %d\n", errno);
        return 1;
    }

    //Check for eBPF CORE support
    if(stat("/sys/kernel/btf/vmlinux", &stat_tmp)) {
        printf("eBPF CORE not supported by this kernel.\n");
        return 1;
    }
        

    // Store the System RAM ranges from /proc/iomem
    if((err = store_system_ram_range(&ranges, &range_count))) return err;

    // Load eBPF prog
    if((err = load_ebpf_prog(&skel, &map))) return err;
        
    // Get parameters to perform phys_to_virt translations
    if((err = get_phys_to_virt_offset(map))) goto cleanup;
    
    // Open output file
    file = fopen(argv[1], "w+");
    if(!file) {
	  perror("Failed to open file for writing");
      goto cleanup;
    }

    // Prepare the LiME header
    header.magic = 0x4C694D45;
    header.version = 1;

    // Loop through the system RAM ranges and call read_kernel_memory with start, end
    size_t written, chunk_size;
    uintptr_t chunk_start, chunk_end, phy_end, virt_addr;
    int key = 0;
    for (size_t i = 0; i < range_count; i++)
    {
        chunk_start = ranges[i].start;
        phy_end = ranges[i].end;
        if((err = write_lime_header_to_file(file, chunk_start, phy_end))) goto cleanup;

        printf("Dumping Range: 0x%lx-0x%lx\n", chunk_start, phy_end);
        while (chunk_start <= phy_end)
        {
            // Trigger read chunk from kernel memory
            chunk_end = (phy_end - chunk_start + 1 > HUGE_PAGE_SIZE) ? chunk_start + HUGE_PAGE_SIZE - 1 : phy_end;
            chunk_size = chunk_end - chunk_start + 1;
            virt_addr = phys_to_virt(chunk_start);
            read_kernel_memory(virt_addr, chunk_size);

            // Retrieve the content
            if (!bpf_map__lookup_elem(map, &key, sizeof(int), &ebpf_buf, sizeof(struct ebpf_buf), 0))
            {
                if((err = ebpf_buf.ret_code)) {
                    fprintf(stderr, "Error reading kernel memory at address 0x%lx, size: %zu\n", virt_addr, chunk_size);
                    goto cleanup;
                }

                written = fwrite(ebpf_buf.buf, 1, chunk_size, file);
                if (written <= 0)
                {
                    fprintf(stderr, "Error writing to file\n");
                    goto cleanup;
                }
            }
            else
            {
                fprintf(stderr, "Failed to read map: %d\n", errno);
                goto cleanup;
            }
            // Move to the next chunk
            chunk_start = chunk_end + 1;

        }
    }

    // Cleanup: free ranges, destroy link, and close BPF object
    cleanup:
        if(ranges) free(ranges);
        if(skel) lemon_ebpf__destroy(skel);
        if(file) fclose(file);

    return 0;
}
