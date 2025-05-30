#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/capability.h>
#include <unistd.h>

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

/* Ethernet frame structure for XDP trigger packets */
struct trigger_frame {
    struct ethhdr eth_header;
    struct read_mem_args args;
    char padding[ETH_ZLEN - sizeof(struct ethhdr) - sizeof(struct read_mem_args)];
} __attribute__((packed));

#define IORESOURCE_MEM		        0x00000200
#define IORESOURCE_SYSRAM	        0x01000000
#define IORESOURCE_BUSY		        0x80000000
#define IORESOURCE_SYSTEM_RAM		(IORESOURCE_MEM|IORESOURCE_SYSRAM)
#define SYSTEM_RAM_FLAGS                (IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY)

extern int check_capability(const cap_value_t cap);

/* eBPF memory read program skeleton and fd of the XDP program */
int read_kernel_memory_xdp_fd;
struct mem_ebpf *mem_ebpf_skel;

/* XDP attachment and network trigger resources */
int ifindex = -1;
int raw_sockfd = -1;
struct bpf_link *bpf_prog_link = NULL;
const char *loopback_interface = "lo";

/* File descriptor and mmap() pointer associated to the eBPF map.*/
int read_mem_result_fd;
struct read_mem_result *read_mem_result;

/* Offset used to perform physical to virtual address translation in x86 and ARM64 */
#ifdef __TARGET_ARCH_x86
    static uintptr_t v2p_offset;
#elif __TARGET_ARCH_arm64
    static int64_t v2p_offset;
#endif

/*Address of root of struct resources list (physical memory regions list) */
static uintptr_t iomem_resource;

#if defined(__TARGET_ARCH_arm64)
   /*
    * @brief Check if memory mapping respects the given address
    * @param addr: The address to check
    *
    * Attempts to mmap a 1-byte region at the specified address. If the mmap operation is successful 
    * and the address is valid (greater than or equal to the specified address) the function returns 
    * true. Otherwise, it returns false.
    * 
    * @return: true if the mmap succeeds at addr, false otherwise.
    */
    static bool is_mmap_respecting_address(void *addr) {
        const size_t size = 1;
        void *mapped_addr = mmap(addr, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapped_addr == MAP_FAILED) {
            return false;
        }
        
        if (munmap(mapped_addr, size) == -1) {
            perror("Failed to munmap");
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
    * @brief Determine the actual virtual address bits for ARM64
    *
    * Determines the number of virtual address bits used by the system on ARM64 
    * by checking the mmap behavior for various address values defined in arch/arm64/Kconfig. 
    * The function first checks the most common virtual address bit settings (48 and 52), 
    * then falls back to testing other possible values (47, 42, 39, 36) if necessary. 
    * @return Number of virtual address bits used (e.g., 48, 52).
    */
    static unsigned long arm64_vabits_actual() {
        unsigned long vabits = 0;

        /* VA_BITS = 48 is probably the most common check it first */
        if (is_mmap_respecting_address((void*)(1ul << (48 - 1)))) {
            if (is_mmap_respecting_address((void*)(1ul << (52 - 1)))) {
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
#endif // __TARGET_ARCH_arm64

/*
 * init_mmap() - Initializes a shared memory mapping for reading memory results from eBPF
 *
 * Retrieves the file descriptor for the BPF map and creates a shared memory mapping
 * to allow user space to access the memory read results.
 */
static int init_mmap() {
    
    read_mem_result_fd = bpf_map__fd(mem_ebpf_skel->maps.read_mem_array_map);
    if(read_mem_result_fd < 0)
        return read_mem_result_fd;

    read_mem_result = (struct read_mem_result *)mmap(NULL, sizeof(struct read_mem_result), PROT_READ | PROT_WRITE, MAP_SHARED, read_mem_result_fd, 0);
    if (read_mem_result == MAP_FAILED) {
        return errno;
    }

    return 0;
}

/*
 * init_raw_socket() - Create and bind a raw socket for sending Ethernet frames
 *
 * Creates a raw socket with ETH_P_ALL protocol to send custom Ethernet frames,
 * and binds it to loopback interface.
 * Returns 0 on success, negative errno value on failure.
 */
static int init_raw_socket(void) {
    struct sockaddr_ll sll;

    /* Create raw socket */
    raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sockfd < 0) {
        perror("Failed to create raw socket for XDP trigger");
        return -errno;
    }

    /* Bind raw socket to loopback interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(raw_sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Failed to bind raw socket to interface");
        close(raw_sockfd);
        raw_sockfd = -1;
        return -errno;
    }

    return 0;
}

/*
 * load_ebpf_mem_progs() - Initialize and attach eBPF programs for memory access
 *
 * Opens, loads, attaches the eBPF programs, and sets up shared memory. 
 * Returns 0 on success or a negative error code on failure.
 */
int load_ebpf_mem_progs() {
    int ret;

    /* Check if we have sufficient capabilities to set RLIMIT_MEMLOCK (required by libbpf...)*/
    if((check_capability(CAP_PERFMON) <= 0) && (check_capability(CAP_SYS_ADMIN) <= 0)) {
        WARN("LEMON does not have CAP_PERFMON needed to modify RLIMIT_MEMLOCK");
    }

    /* Open the BPF object file */
    mem_ebpf_skel = mem_ebpf__open();
    if(!mem_ebpf_skel) {
        perror("Failed to open BPF skeleton");
        return errno;
    }

    /* ARM64 phys to virt translation requires two values, one of the two (CONFIG_ARM64_VA_BITS)
     * might not be available from eBPF so we try to compute it at runtime here and we pass it to
     * eBPF.
     */
    #if defined(__TARGET_ARCH_arm64)
        unsigned long vabits = arm64_vabits_actual();
        if (vabits == 0) {
            WARN("Failed to determine runtime virtual address bits, defaulting to 48");
            vabits = 48;
        }
        mem_ebpf_skel->data->runtime_va_bits = vabits;
    #endif

    /* Load the BPF objectes */
    if (mem_ebpf__load(mem_ebpf_skel)) {
        perror("Failed to load BPF object");
        return errno;
    }

    /* Attach the uprobe to the 'read_kernel_memory' function in the current executable */
    bpf_prog_link = bpf_program__attach(mem_ebpf_skel->progs.read_kernel_memory_uprobe);
    if (!bpf_prog_link) {
        fprintf(stderr, "Failed to attach eBPF Uprobe program, use XDP fallback one...\n");
        
        /* Check if can create raw sockets for XDP */
        if (check_capability(CAP_NET_RAW) <= 0) {
            WARN("LEMON does not have CAP_NET_RAW to create raw sockets for XDP");
        }
        
        /* Get loopback interface index by name "lo" (usually 1) */
        ifindex = if_nametoindex(loopback_interface);
        if (ifindex <= 0) {
            perror("Failed to get interface index");
            return -errno;
        }
        
        /* Attach XDP program to the interface */
        bpf_prog_link = bpf_program__attach_xdp(mem_ebpf_skel->progs.read_kernel_memory_xdp, ifindex);
        if (!bpf_prog_link) {
            fprintf(stderr, "Failed to attach XDP program to interface %s (index: %d)\n", loopback_interface, ifindex);
        }
        
        /* Create socket for sending trigger packets */
        if ((ret = init_raw_socket())) {
            return ret;
        }
    }
    
    /* Create the mmap */
    if((ret = init_mmap())) {
        return ret;
    }

    return 0;
}

/*
 * cleanup_mem_ebpf() - Unmaps the shared memory region used to access map and free eBPF resources.
 */
void cleanup_mem_ebpf() {
    if(mem_ebpf_skel) {
        if(read_mem_result) munmap(read_mem_result, sizeof(struct read_mem_result));
        mem_ebpf__destroy(mem_ebpf_skel);
    }
    
    /* Destroy bpf_link if it exists*/
    if (bpf_prog_link) {
        bpf_link__destroy(bpf_prog_link);
        bpf_prog_link = NULL;
    }

    /* Close raw socket if it's open */
    if (raw_sockfd) {
        close(raw_sockfd);
        raw_sockfd = -1;
    }
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
        return phy_addr - v2p_offset;
    #else
        return phy_addr;
    #endif
}

/*
 * send_xdp_trigger_packet() - Send Ethernet frame to trigger XDP program
 * @addr: Virtual address of the memory region to read
 * @size: Size of the memory region to read
 * 
 * Constructs and sends an Ethernet frame with the memory read arguments as payload
 * to the loopback interface triggering the XDP program to perform the read.
 * Uses a minimal Ethernet frame with broadcast destination.
 * Returns 0 on success, negative errno value on failure.
 */
static int send_xdp_trigger_packet(const uintptr_t addr, const size_t size) {
    struct trigger_frame frame;
    struct sockaddr_ll dest_addr;
    ssize_t sent_bytes;
    
    /* Initialize frame structure */
    memset(&frame, 0, sizeof(frame));
    
    /* Setup Ethernet header, and use broadcast address for simplicity */
    memset(frame.eth_header.h_dest, 0xFF, ETH_ALEN);    /* Broadcast destination */
    memset(frame.eth_header.h_source, 0x00, ETH_ALEN);
    frame.eth_header.h_proto = htons(0x0800);
    
    /* Setup memory read arguments in payload */
    frame.args.addr = addr;
    frame.args.size = size;
    
    /* Setup destination address */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_ifindex = ifindex;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_halen = ETH_ALEN;
    memset(dest_addr.sll_addr, 0xFF, ETH_ALEN);  /* Broadcast destination */
    
    /* Send the frame */
    sent_bytes = sendto(raw_sockfd, &frame, sizeof(frame), 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    if (sent_bytes < 0) {
        perror("Failed to send XDP trigger packet");
        return -errno;
    }
    
    /* For raw packets, partial send should not happen */
    if (sent_bytes != sizeof(frame)) {
        fprintf(stderr, "Incomplete packet send: %zd of %zu bytes\n", 
                sent_bytes, sizeof(frame));
        return -EIO;
    }
    
    return 0;
}

/*
 * read_kernel_memory() - Trigger eBPF UProbe or XDP to read kernel virtual memory
 * @addr: Virtual address of the memory region to read
 * @size: Size of the memory region to read
 * @data: Pointer to store the output data
 *
 * This function triggers an eBPF UProbe or XDP to read the specified memory region in kernel space.
 * The function is marked with `noinline` and `optnone` to ensure the code is not optimized or inlined by the compiler.
 */
int __attribute__((noinline, optnone)) read_kernel_memory(const uintptr_t addr, const size_t size, __u8 **restrict data) {
    /* If the Uprobe support is not active in kernel, use XDP to read the memory*/
    if(raw_sockfd > 0) {
        int ret;
        
        /* Send XDP trigger packet */
        ret = send_xdp_trigger_packet(addr, size);
        if (ret < 0) {
            read_mem_result->ret_code = ret;
            return ret;
        }
    }

    *data = read_mem_result->buf;
    return read_mem_result->ret_code;
}

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
 *
 * Initializes the physical-to-virtual address mapping and retrieves System RAM virtual address ranges 
 * from kernel or /proc/iomem.
 * Returns 0 on success or an error code on failure.
 */
int init_translation(struct ram_regions *restrict ram_regions) {
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
