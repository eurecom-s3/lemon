// Handle pages that are handed over to the hypervisor and no longer accessible
// in EL1. This issues was first encountered on Samsung's Qualcomm based phones

#include <stdio.h>
#include <stdint.h>
#include "lemon.h"

// TODO: page's size is configuration depended, find a way to compute it at
// runtime. It's often 64 or 80 bytes.
#define sizeof_page 64
#define log2_sizeof_page 6
#define VA_BITS 39
#define PAGE_SHIFT 12
#define STRUCT_PAGE_MAX_SHIFT	(log2_sizeof_page)
#define VMEMMAP_SHIFT	(PAGE_SHIFT - STRUCT_PAGE_MAX_SHIFT)
#define VMEMMAP_START		(-(1ul) << (VA_BITS - VMEMMAP_SHIFT))
#define __pfn_to_page(pfn)	(vmemmap + (pfn))

extern int read_kernel_memory(const uintptr_t addr, const size_t size, unsigned char **restrict data);

unsigned char* secure_page_placeholder[HUGE_PAGE_SIZE] = {(unsigned char*)"Lemon error: SECURE PAGE unable to dump"};

// Defined in arch/arm64/include/asm/pgtable.h
//  #define vmemmap			((struct page *)VMEMMAP_START - (memstart_addr >> PAGE_SHIFT))
static uintptr_t vmemmap;

// as defined in kernel_platform/msm-kernel/drivers/soc/qcom/secure_buffer.c
// from Samsung Qualcomm source
#define SECURE_PAGE_MAGIC 0xEEEEEEEE

// Minimal definition of the struct page (and dependencies)
// excerpt of linux/mm_types.h
typedef unsigned long pgoff_t;

struct list_head {
	struct list_head *next, *prev;
};
struct address_space {
    void* _placeholder;
};

struct page {
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * lruvec->lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			struct list_head lru;

			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			pgoff_t index;		/* Our offset within mapping. */
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			unsigned long private;
		};
    // [...] other stuff
    };
};

void init_secure_pages_handler(int64_t memstart_addr) {
    vmemmap = VMEMMAP_START - (memstart_addr >> PAGE_SHIFT) * sizeof_page;
    printf("vmemmap: %lx\n", vmemmap);
}

bool is_secure_page(uintptr_t page_start) {
    struct page* p;
    uint8_t *data = NULL;
    const uintptr_t pfn = page_start >> PAGE_SHIFT;
    const uintptr_t addr = vmemmap + pfn * sizeof_page;
    
    if (read_kernel_memory(addr, sizeof(struct page), &data)) {
        fprintf(stderr, "Failed to read struct pages for pfn %lx at kernel address: %lx", pfn, addr);
        return false;
    };
    p = (struct page*) data;

    return p->private == SECURE_PAGE_MAGIC;
}
