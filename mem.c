#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "lemon.h"
#include "lemon.ebpf.skel.h"

/* Offset used to perform physical to virtual address translation */
uintptr_t phy_to_virt_offset;

/* Userland copy of the memory channel content */
struct read_mem_result read_mem_result;

/* Memory channel map   */
struct bpf_map *read_mem_map;

/*
 * phys_to_virt() - it translates a physical address to a virtual one using kernel direct mapping.
 * @phy_addr: a pointer to a string containing the name of the file to look up.
 *
 * The translation method depends on the architecture.
 * At the moment we support only x86_64 and ARM64.
 * 
 */
static inline uintptr_t phys_to_virt(const uintptr_t phy_addr) {
    #ifdef __TARGET_ARCH_x86
        return phy_addr + phy_to_virt_offset;
    #elif __TARGET_ARCH_arm64
        return (phy_addr - phy_to_virt_offset) | 0xffff000000000000;
    #else
        return phy_addr;
    #endif
}

/*
 *  read_kernel_memory() - it triggers the eBPF program and reads virtual memory area
 *  @addr: virtual address of the memory area to be read
 *  @size: size of the memory area to read
 *  @data: pointer to the output data
 * 
 *  When we call this function the eBPF UProbe program is triggered, 
 *  reading the corresponding memory region in kernel space.
 *  We force non inlining and no optimization to permit easy UProbe attach.
 * 
 */
int __attribute__((noinline, optnone)) read_kernel_memory(const uintptr_t addr, const size_t size, uint8_t **restrict data)
{
    int key = 0;

    if (bpf_map__lookup_elem(read_mem_map, &key, sizeof(int), &read_mem_result, sizeof(struct read_mem_result), 0))
    {
        fprintf(stderr, "Failed to read read_mem_map: %d\n", errno);
        data = NULL;
        return errno;
    }

    if(read_mem_result.ret_code) {
        fprintf(stderr, "Error reading kernel memory at address 0x%lx, size: 0x%zx\n", addr, size);
        data = NULL;
        return read_mem_result.ret_code;
    }

    *data = read_mem_result.buf;
    return 0;
}

/*
 *  get_phys_to_virt_offset() - it reads the phys_to_virt_offset that permit direct mapping translation
 *                              of physical addresses in virtual ones.
 * 
 *  It looks for the kernel symbol in /proc/kallsyms that contains the offset used in different
 *  architectures to translate physical to virtual addresses using direct mapping. 
 * 
 */
static int get_phys_to_virt_offset()
{
    FILE *fp;
    char line[256];
    uintptr_t kallsyms_symb_addr = 0;
    int err;
    uint8_t *data = NULL;

    #ifdef __TARGET_ARCH_x86
        char *symbol = "page_offset_base";
    #elif __TARGET_ARCH_arm64
        char *symbol = "memstart_addr";
    #endif

    /* Open the kallsyms file and look for the symbol in it*/
    fp = fopen("/proc/kallsyms", "r");
    if (!fp)
    {
        perror("Failed to open /proc/kallsyms");
        return errno;
    }

    while (fgets(line, sizeof(line), fp))
        if (strstr(line, symbol) && (sscanf(line, "%lx", &kallsyms_symb_addr) == 1)) break;
    fclose(fp);

    if (!kallsyms_symb_addr)
    {
        fprintf(stderr, "%s not found in /proc/kallsyms\n", symbol);
        return EINVAL;
    }

    #ifdef DEBUG
        printf("Symbol %s at 0x%lx\n", symbol, kallsyms_symb_addr);
    #endif

    /* Read the content of the kernel symbol to get the offset of direct mapping region */
    if((err = read_kernel_memory(kallsyms_symb_addr, sizeof(uintptr_t), &data))) return err;
    phy_to_virt_offset = *((uintptr_t *)data);

    #ifdef DEBUG
        printf("Direct mapping offset: 0x%lx\n", phy_to_virt_offset);
    #endif

    return 0;
}

/*
 *  get_iomem_regions() - it reads and stores System RAM virtual address ranges from /proc/iomem 
 *  @regions: pointer that will contains all valid regions
 *
 *  It looks for "System RAM" memory regions in /proc/iomem, translate the start and end physical
 *  addresses in virtual ones and saves them into the ram_regions array.
 * 
 */
static int get_iomem_regions(struct ram_regions *restrict ram_regions)
{
    FILE *fp;
    char line[256];
    int slot_availables;
    uintptr_t start, end;

    /* Open the /proc/iomem and parse only "System RAM" regions */
    fp = fopen("/proc/iomem", "r");
    if (!fp)
    {
        perror("Failed to open /proc/iomem");
        return errno;
    }

    /* Initial RAM regions allocations */
    ram_regions->num_regions = 0;
    slot_availables = 8;

    ram_regions->regions = (struct ram_range *)malloc(slot_availables * sizeof(struct ram_range));
    if (!ram_regions->regions)
    {
        perror("Failed to allocate memory for RAM ranges");
        fclose(fp);
        return errno;
    }
    
    /* Look only for "System RAM" regions */
    while (fgets(line, sizeof(line), fp))
    {
        if (strstr(line, "System RAM") && sscanf(line, "%lx-%lx", &start, &end) == 2)
        {
            /* If the array is full, reallocate to increase its size */
            if (ram_regions->num_regions >= slot_availables)
            {
                slot_availables *= 2;
                ram_regions->regions = 
                    (struct ram_range *)realloc(ram_regions->regions, slot_availables * sizeof(struct ram_range));
                if (!ram_regions->regions)
                {
                    perror("Failed to reallocate memory for RAM ranges");
                    fclose(fp);
                    return errno;
                }
            }

            /* Convert to virtual addresses */
            (ram_regions->regions)[ram_regions->num_regions].start = phys_to_virt(start);
            (ram_regions->regions)[ram_regions->num_regions].end = phys_to_virt(end);
            (ram_regions->num_regions)++;
            
        }
    }
    fclose(fp);

    return 0;
}

/*
 *  get_memory_regions() - it initializes the physical to virtual address translation mechanism
    and returns System RAM virtual address ranges from /proc/iomem 
 *  @regions: pointer that will contains all valid regions
 *  @skel: eBPF skeleton
 *
 *  It determines the offset for physical to virtual address translation and then returns the
 *  memory regions array.
 * 
 */
int get_memory_regions(struct ram_regions *restrict ram_regions, struct lemon_ebpf *restrict skel) {
    int err;

    /* Get the read_mem_map */
    read_mem_map = skel->maps.read_mem_array_map; 

    /* Determine the offset for translations */
    if((err = get_phys_to_virt_offset())) return err;

    return get_iomem_regions(ram_regions);
}