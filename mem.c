#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "lemon.h"
#include "ebpf/mem.ebpf.skel.h"

/* File descriptor and mmap() pointer associated to the eBPF map.*/
int read_mem_result_fd;
struct read_mem_result *read_mem_result;

/* Offset used to perform physical to virtual address translation in x86 and ARM64 */
#ifdef __TARGET_ARCH_x86
    static uintptr_t page_offset_base;
#elif __TARGET_ARCH_arm64
    static int64_t memstart_addr;
    #ifndef CORE
        static uintptr_t page_offset;
    #endif
#endif

/*
 * init_mmap() - Initializes a shared memory mapping for reading memory results from eBPF
 * @skel: eBPF skeleton containing the map to be used
 *
 * Retrieves the file descriptor for the BPF map and creates a shared memory mapping
 * to allow user space to access the memory read results.
 */
int init_mmap(struct mem_ebpf *restrict skel) {
    
    read_mem_result_fd = bpf_map__fd(skel->maps.read_mem_array_map);
    if(read_mem_result_fd < 0)
        return read_mem_result_fd;

    read_mem_result = (struct read_mem_result *)mmap(NULL, sizeof(struct read_mem_result), PROT_READ | PROT_WRITE, MAP_SHARED, read_mem_result_fd, 0);
    if (read_mem_result == MAP_FAILED) {
        return errno;
    }

    return 0;
}

/*
 * cleanup_mmap() - Unmaps the shared memory region used for memory memory.
 */
void cleanup_mmap() {
    if(read_mem_result) munmap(read_mem_result, sizeof(struct read_mem_result));
}

/*
 * phys_to_virt() - Convert a physical address to a virtual address using direct mapping
 * @phy_addr: Physical address to translate
 *
 * Performs architecture-specific translation using kernel direct mapping.
 * Currently supports x86_64 and ARM64 only.
 */

uintptr_t phys_to_virt(const uintptr_t phy_addr) {
    #ifdef __TARGET_ARCH_x86
        return phy_addr + page_offset_base;
    #elif __TARGET_ARCH_arm64
        uintptr_t vaddr = phy_addr - memstart_addr;
        #ifndef CORE
            /* If in CO-RE mode the translation will be finished in the eBPF program */
            vaddr |= page_offset;
        #endif
        return vaddr;
    #else
        return phy_addr;
    #endif
}

/*
 * read_kernel_memory() - Trigger eBPF UProbe to read kernel virtual memory
 * @addr: Virtual address of the memory region to read
 * @size: Size of the memory region to read
 * @data: Pointer to store the output data
 *
 * This function triggers an eBPF UProbe to read the specified memory region in kernel space.
 * The function is marked with `noinline` and `optnone` to ensure the code is not optimized or inlined by the compiler.
 */
int __attribute__((noinline, optnone)) read_kernel_memory(const uintptr_t addr, const size_t size, __u8 **restrict data)
{
    *data = read_mem_result->buf;
    return read_mem_result->ret_code;
}

#if defined(__TARGET_ARCH_arm64) && !defined(CORE)
   /*
    * is_mmap_respecting_address() - Check if memory mapping respects the given address
    * @addr: The address to check
    *
    * Attempts to mmap a 1-byte region at the specified address. If the mmap operation is successful 
    * and the address is valid (greater than or equal to the specified address), the function returns 
    * true. Otherwise, it returns false.
    */
    static bool is_mmap_respecting_address(void *addr) {
        unsigned int size = getpagesize();
        void *mapped_addr = mmap(addr, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapped_addr == MAP_FAILED) {
            return false;
        }
        
        if (munmap(mapped_addr, size) == -1) {
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
    * arm64_vabits_actual() - Determine the actual virtual address bits for ARM64
    *
    * Determines the number of virtual address bits used by the system on ARM64 
    * by checking the mmap behavior for various address values defined in arch/arm64/Kconfig. 
    * The function first checks the most common virtual address bit settings (48 and 52), 
    * then falls back to testing other possible values (47, 42, 39, 36) if necessary. 
    * Returns the number of virtual address bits used (e.g., 48, 52).
    */
    static unsigned long arm64_vabits_actual() {
        unsigned long vabits = 0;

        /* VA_BITS = 48 is probably the most common check it first */
        if (is_mmap_respecting_address((void*)(1ul << 47))) {
            if (is_mmap_respecting_address((void*)(1ul << 51))) {
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
#endif

/*
 * init_phys_to_virt() - Initialize the physical-to-virtual address translation offset
 *
 * Opens /proc/kallsyms, searches for the appropriate symbol (e.g., "page_offset_base" or 
 * "memstart_addr") based on architecture, and retrieves the physical-to-virtual address 
 * translation offset. Returns 0 on success, or an error code on failure.
 */
static int init_phys_to_virt()
{
    FILE *fp;
    char line[256];
    uintptr_t kallsyms_symb_addr = 0;
    int err;
    __u8 *data = NULL;

    /* Symbol to be located in /proc/kallsyms */
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

    /* Look for the symbol */
    while (fgets(line, sizeof(line), fp))
        if (strstr(line, symbol) && (sscanf(line, "%lx", &kallsyms_symb_addr) == 1)) break;
    if(fclose(fp)) {
        perror("Fail to close /proc/kallsyms");
        return errno;
    }

    if (!kallsyms_symb_addr)
    {
        fprintf(stderr, "%s not found in /proc/kallsyms\n", symbol);
        return EIO;
    }

    /* Make sure we can use the same read for signed and unsigned offsets (arm/intel) */
    _Static_assert(sizeof(uintptr_t) == sizeof(int64_t), "sizeof(uintptr_t) != sizeof(int64_t)");
    
    /* Read the content of the kernel symbol to get the offset of direct mapping region */
    if((err = read_kernel_memory(kallsyms_symb_addr, sizeof(uintptr_t), &data))) return err;
    
    // TODO Pass to _stext trick for x64

    /* We are able now to translate phys to virt addresses for X64. ARM64 instead is more complex 
     * and require two values, one of the two (CONFIG_ARM64_VA_BITS) available only in the eBPF 
     * CO-RE program or determined at runtime here for non CO-RE ones.
     */
    #ifdef __TARGET_ARCH_x86
        page_offset_base = *((uintptr_t *)data);
    
    #elif __TARGET_ARCH_arm64
        memstart_addr = *((int64_t *)data);
        
        #ifndef CORE
            /* If the kernel is not CORE we determibne the CONFIG_ARM64_VA_BITS using the runtime value. */
            unsigned long vabits = arm64_vabits_actual();
            if (vabits == 0) {
                perror("Failed to determine virtual address bits, defaulting to 48");
                vabits = 48;
            }
            page_offset = -1L << vabits;
        #endif
    
    #endif

    return 0;
}

/*
 * get_iomem_regions() - Parse /proc/iomem to extract "System RAM" regions
 * @ram_regions: Pointer to store the extracted RAM regions
 *
 * Opens /proc/iomem, searches for "System RAM" regions, and populates the provided
 * ram_regions struct with the start and end addresses of each region. The function
 * reallocates memory as needed to accommodate additional regions. Returns 0 on success,
 * or an error code on failure.
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

    ram_regions->regions = (struct mem_range *)malloc(slot_availables * sizeof(struct mem_range));
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
                    (struct mem_range *)realloc(ram_regions->regions, slot_availables * sizeof(struct mem_range));
                if (!ram_regions->regions)
                {
                    perror("Failed to reallocate memory for RAM ranges");
                    fclose(fp);
                    return errno;
                }
            }

            /* Convert to virtual addresses */
            (ram_regions->regions)[ram_regions->num_regions].start = start;
            (ram_regions->regions)[ram_regions->num_regions].end = end;
            (ram_regions->num_regions)++;
            
        }
    }
    if(fclose(fp)) {
        perror("Fail to close /proc/iomem");
        return errno;
    }

    return 0;
}

/*
 * toggle_kptr() - Toggle the kernel.kptr_restrict sysctl setting
 *
 * Reads and toggles /proc/sys/kernel/kptr_restrict between 0 and its original value.
 * Caches the original value on first call. Returns 0 on success, or an error code on failure.
 */
static int toggle_kptr(void) {
    static int orig_kptr_status = - 1;

    struct stat stat_tmp;
    FILE *kptr_fd;
    int current_kptr_status, new_kptr_status, err = 0;

    /* If kptr_restrict does not exists (?) do nothing */
    if(stat("/proc/sys/kernel/kptr_restrict", &stat_tmp)) {
        perror("/proc/sys/kernel/kptr_restrict not found");
        return 0;
    }

    /* Open the file */
    if(!(kptr_fd = fopen("/proc/sys/kernel/kptr_restrict", "r+"))) {
        perror("Failed to open /proc/sys/kernel/kptr_restrict");
        return errno;
    }
    
    /* Read current kptr_status */
    if(fscanf(kptr_fd, "%d", &current_kptr_status) == EOF) {
        perror("Fail to read /proc/sys/kernel/kptr_restrict");
        err = errno;
        goto cleanup;
    }
    rewind(kptr_fd);

    /* Save the original value */
    if(orig_kptr_status == -1) {
        orig_kptr_status = current_kptr_status;
    }

    /* Toggle the kptr_restrict value*/
    new_kptr_status = (current_kptr_status > 0) ? 0 : orig_kptr_status;
    if(fprintf(kptr_fd, "%d", new_kptr_status) < 0) {
        err = EIO;
        goto cleanup;
    }

    cleanup:
    if(kptr_fd) {
        if(fclose(kptr_fd)) {
            perror("Fail to close /proc/sys/kernel/kptr_restrict");
            return errno;
        }
    }

    return err;
}

/*
 * get_memory_regions() - Initialize phys-to-virt translation and extract System RAM regions
 * @ram_regions: Output pointer for storing valid memory regions
 * @skel: eBPF skeleton used for memory access
 *
 * Temporarily disables kptr restriction, initializes the physical-to-virtual address mapping,
 * restores the restriction, and retrieves System RAM virtual address ranges from /proc/iomem.
 * Returns 0 on success or an error code on failure.
 */
int get_memory_regions(struct ram_regions *restrict ram_regions, struct mem_ebpf *restrict skel) {
    int err;

    /* Disable KPTR censorship */
    if((err = toggle_kptr())) return err;

    /* Determine the offset for translations */
    if((err = init_phys_to_virt())) return err;

    /* Restore original KPTR censhorship level*/
    if((err = toggle_kptr())) return err;

    return get_iomem_regions(ram_regions);
}
