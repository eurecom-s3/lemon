#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/capability.h>

#include "lemon.h"
#include "ebpf/mem.ebpf.skel.h"

/* Kernel definition of a memory region (from include/linux/ioport.h) 
 * !!! WARNING !!! In theory this struct can change in different kernel versions
 *                 However last time changes was in Linux 4.6
 */
struct resource {
    unsigned long long start;
    unsigned long long end;
    const char *name;
    unsigned long flags;
    unsigned long desc;
    struct resource *parent, *sibling, *child;
};

#define IORESOURCE_MEM		        0x00000200
#define IORESOURCE_SYSRAM	        0x01000000
#define IORESOURCE_BUSY		        0x80000000
#define IORESOURCE_SYSTEM_RAM		(IORESOURCE_MEM|IORESOURCE_SYSRAM)
#define SYSTEM_RAM_FLAGS            (IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY)

extern int check_capability(const cap_value_t cap);

/* File descriptor and mmap() pointer associated to the eBPF map.*/
int read_mem_result_fd;
struct read_mem_result *read_mem_result;

/* Offset used to perform physical to virtual address translation in x86 and ARM64 */
#ifdef __TARGET_ARCH_x86
    static uintptr_t v2p_offset;
#elif __TARGET_ARCH_arm64
    static int64_t v2p_offset;
    #ifdef(CORE)
        static uintptr_t page_offset;
    #endif
#endif

/*Address of root of struct resources list (physical memory regions list) */
static uintptr_t iomem_resource;

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
        return phy_addr + v2p_offset;
    #elif __TARGET_ARCH_arm64
        uintptr_t vaddr = phy_addr - v2p_offset;
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
    if ((sscanf(line, "%lx %*c %255s\n",current_symb_addr, current_symb_name) != 2) || strncmp(current_symb_name, symbol, strlen(symbol)))
        return 0;

    /* Check that address is not 0 */
    return current_symb_addr != 0;
}

/*
 * parse_kallsyms() - Parse /proc/kallsyms extracting needed symbols
 *
 * Opens /proc/kallsyms, searches for the appropriate symbol (e.g., "page_offset_base" or 
 * "memstart_addr" and "iomem_resource") based on architecture, and retrieves the physical-to-virtual address 
 * translation offset and the pointer to the tree of physical memory regions. Returns 0 on success, or an error code on failure.
 */
static int parse_kallsyms()
{
    FILE *fp;
    char line[256];
    __u8 *data = NULL;
    uintptr_t current_symb_addr = 0;
    int err;

    /* Make sure we can use the same read for signed and unsigned offsets (arm/intel) */
    _Static_assert(sizeof(uintptr_t) == sizeof(int64_t), "sizeof(uintptr_t) != sizeof(int64_t)");

    /* Check for capabilities */
    if((check_capability(CAP_SYSLOG) <= 0)) {
        fprintf(stderr, "LEMON does not have CAP_SYSLOG to read addresses from /proc/kallsyms\n");
        return EPERM;
    }

    /* Symbol to be located in /proc/kallsyms */
    iomem_resource = 0;
    v2p_offset = 0;

    #ifdef __TARGET_ARCH_x86
        char *v2p_symbol = "page_offset_base";
    #elif __TARGET_ARCH_arm64
        char *v2p_symbol = "memstart_addr";
    #endif

    /* Open the kallsyms file and look for symbols in it*/
    fp = fopen("/proc/kallsyms", "r");
    if (!fp)
    {
        perror("Failed to open /proc/kallsyms");
        return errno;
    }

    /* Look for all the symbols */
    while (fgets(line, sizeof(line), fp)) {

        /* Check if all the symbols are already found */
        if(iomem_resource && v2p_offset) break;

        /* Look for symbols */
        if(!iomem_resource && parse_kallsyms_line(line, "iomem_resource", &current_symb_addr)) {
            iomem_resource = current_symb_addr;
            continue;
        }

        if(!v2p_offset && parse_kallsyms_line(line, v2p_symbol, &current_symb_addr)) {

            /* Read it to obtain the offset */
            if((err = read_kernel_memory(current_symb_addr, sizeof(uintptr_t), &data))) break;
            #ifdef __TARGET_ARCH_x86
                v2p_offset = *((uintptr_t *)data);
            #elif __TARGET_ARCH_arm64
                v2p_offset = *((int64_t *)data);
            #endif
            continue;
        }
    }

    if(fclose(fp)) {
        perror("Fail to close /proc/kallsyms");
        return errno;
    }

    /* Check if all the virtual to phisical offset is found */
    if (!v2p_offset)
    {
        fprintf(stderr, "Symbol %s not found in /proc/kallsyms\n", v2p_symbol);
        return EIO;
    }

    /* We are able now to translate phys to virt addresses for X64. ARM64 instead is more complex 
     * and require two values, one of the two (CONFIG_ARM64_VA_BITS) available only in the eBPF 
     * CO-RE program or determined at runtime here for non CO-RE ones.
     *
     * TODO: false! it does not depends by CO-RE, but on availability of the kernel config (see libbpf)
     */
    #if defined(__TARGET_ARCH_arm64) && !defined(CORE)
        /* If the kernel is not CORE we determine the CONFIG_ARM64_VA_BITS using the runtime value. */
        unsigned long vabits = arm64_vabits_actual();
        if (vabits == 0) {
            fprintf(stderr, "Failed to determine virtual address bits, defaulting to 48\n");
            vabits = 48;
        }
        page_offset = -1L << vabits;

    #endif

    return 0;
}

/*
 * get_iomem_regions_user() - Parse /proc/iomem to extract "System RAM" regions
 * @ram_regions: Pointer to store the extracted RAM regions
 *
 * Opens /proc/iomem, searches for "System RAM" regions, and populates the provided
 * ram_regions struct with the start and end addresses of each region. The function
 * reallocates memory as needed to accommodate additional regions. Returns 0 on success,
 * or an error code on failure.
 */
static int get_iomem_regions_user(struct ram_regions *restrict ram_regions)
{
    FILE *fp;
    char line[256];
    int slot_availables;
    uintptr_t start, end;
    int cap_ret;

    /* Check if we have CAP_SYS_ADMIN capability */
    if((cap_ret = check_capability(CAP_SYS_ADMIN)) <= 0) {
        fprintf(stderr, "LEMON does not have CAP_SYS_ADMIN to read /proc/iomem\n");
        return cap_ret;
    }

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

            /* Save region start and end */
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
 * get_iomem_regions_kernel() - Parse struct resources directly in kernel to extract "System RAM" regions
 * @ram_regions: Pointer to store the extracted RAM regions
 *
 * Read struct resources from kernel, and populates the provided
 * ram_regions struct with the start and end addresses of each region. The function
 * reallocates memory as needed to accommodate additional regions. Returns 0 on success,
 * or an error code on failure.
 */
static int get_iomem_regions_kernel(struct ram_regions *restrict ram_regions)
{
    int slot_availables;
    __u8 *data = NULL;
    struct resource *res, *next_res;
    int err;

    /* Initial RAM regions allocations */
    ram_regions->num_regions = 0;
    slot_availables = 8;

    ram_regions->regions = (struct mem_range *)malloc(slot_availables * sizeof(struct mem_range));
    if (!ram_regions->regions)
    {
        perror("Failed to allocate memory for RAM ranges");
        return errno;
    }
    
    /* We follow the implementation of LiME considering only sibling leafs (level 1 only).
     * Is it possible to have "System RAM" regions inside non System RAM regions? I don't think so. 
     */

    /* Obrain the address child of the root struct */
    if((err = read_kernel_memory(iomem_resource, sizeof(struct resource), &data))) {
        fprintf(stderr, "Error reading root struct resource");
        return err;
    }
    res = ((struct resource *)data);
    next_res = res->child;

    /* Walk the sibling list */
    while(next_res) {
        if((err = read_kernel_memory((uintptr_t)next_res, sizeof(struct resource), &data))) {
            fprintf(stderr, "Error reading sibling struct");
            return err;
        }
        res = ((struct resource *)data);

        /* Check if it is a "System RAM" region using flags instead of string (reduce memory copying from kernel to user) */
        if(res->name && ((res->flags & SYSTEM_RAM_FLAGS) == SYSTEM_RAM_FLAGS)) {
            /* If the array is full, reallocate to increase its size */
            if (ram_regions->num_regions >= slot_availables)
            {
                slot_availables *= 2;
                ram_regions->regions = 
                    (struct mem_range *)realloc(ram_regions->regions, slot_availables * sizeof(struct mem_range));
                if (!ram_regions->regions)
                {
                    perror("Failed to reallocate memory for RAM ranges");
                    return errno;
                }
            }

            /* Save region start and end */
            (ram_regions->regions)[ram_regions->num_regions].start = res->start;
            (ram_regions->regions)[ram_regions->num_regions].end = res->end;
            (ram_regions->num_regions)++;
        }

        /* Prepare for next iteration */
        next_res = res->sibling;
    }
    return 0;
}

/*
 * toggle_kptr() - Toggle the kernel.kptr_restrict sysctl setting
 *
 * Reads and toggles /proc/sys/kernel/kptr_restrict between 0 and its original value (only if needed).
 * Caches the original value on first call. Returns 0 on success, or an error code on failure.
 */
 int toggle_kptr(void) {
    static int orig_kptr_status = - 1;

    struct stat stat_tmp;
    FILE *kptr_fd;
    int current_kptr_status, new_kptr_status, cap_ret, err = 0;

    /* If kptr_restrict does not exists (?) do nothing */
    if(stat("/proc/sys/kernel/kptr_restrict", &stat_tmp)) {
        perror("/proc/sys/kernel/kptr_restrict not found");
        return 0;
    }

    /* Open the file */
    if(!(kptr_fd = fopen("/proc/sys/kernel/kptr_restrict", "r"))) {
        perror("Failed to open /proc/sys/kernel/kptr_restrict");
        return errno;
    }
    
    /* Read current kptr_status */
    if(fscanf(kptr_fd, "%d", &current_kptr_status) == EOF) {
        perror("Fail to read /proc/sys/kernel/kptr_restrict");
        err = errno;
        goto cleanup;
    }

    /* Save the original value */
    if(orig_kptr_status == -1) {
        orig_kptr_status = current_kptr_status;
    }

    /* If the original kptr_value is 0 do nothing */
    if(!orig_kptr_status) goto cleanup;

    /* If the value is 1 and we have CAP_SYSLOG is not necessary to toggle it (neigter CAP_SYS_ADMIN!) :) */
    if((orig_kptr_status == 1) && (check_capability(CAP_SYSLOG) > 0)) goto cleanup;

    /* Check CAP_SYS_ADMIN to modify kptr_restrict */
    if((cap_ret = check_capability(CAP_SYS_ADMIN)) <= 0) {
        fprintf(stderr, "LEMON does not have CAP_SYS_ADMIN to modify /proc/sys/kernel/kptr_restrict policy\n");
        err = cap_ret;
        goto cleanup;
    }

    /* Reopen the file in RW mode */
    if(!(kptr_fd = freopen(NULL, "r+", kptr_fd))) {
        perror("Failed to open /proc/sys/kernel/kptr_restrict in RW mode");
        err = errno;
        goto cleanup;
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
 * init_translation() - Initialize phys-to-virt translation and extract System RAM regions
 * @ram_regions: Output pointer for storing valid memory regions
 * @skel: eBPF skeleton used for memory access
 *
 * Initializes the physical-to-virtual address mapping and retrieves System RAM virtual address ranges 
 * from kernel or /proc/iomem.
 * Returns 0 on success or an error code on failure.
 */
int init_translation(struct ram_regions *restrict ram_regions, struct mem_ebpf *restrict skel) {
    int err;

    /* Parse kallsyms looking for symbols needed to initialize translatation system */
    if((err = parse_kallsyms())) return err;

    /* If the iomem_resource symbol is available access to it through eBPF bypassing CAP_SYS_ADMIN
     * Otherwise use /proc/iomem which requires CAP_SYS_ADMIN.
     */

    if(iomem_resource) {
        return get_iomem_regions_kernel(ram_regions);
    }
    else
        return get_iomem_regions_user(ram_regions);
}