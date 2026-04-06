#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <errno.h>
#include <sys/queue.h>

#include "lemon.h"

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

extern int check_capability(const struct lemon_ctx *restrict ctx, const cap_value_t cap);
extern int read_kernel_memory(const uintptr_t addr, const size_t size, unsigned char **restrict data);

struct mem_range *range_new(unsigned long long start, unsigned long long end, bool virtual) {
    if (start >= end)
        return NULL;

    struct mem_range *n = malloc(sizeof(*n));
    if (!n)
        return NULL;

    n->start = start;
    n->end   = end;
    n->virtual = virtual;
    return n;
}


void range_list_free(struct ram_regions *list) {
    struct mem_range *it, *tmp;
    if(!list) return;

    TAILQ_FOREACH_SAFE(it, list, entries, tmp) {
        TAILQ_REMOVE(list, it, entries);  /* sicuro: tmp salva il next prima */
        free(it);
    }

    TAILQ_INIT(list);
}

/* Comparator for qsort – arr elements are struct mem_range *, so qsort
   passes struct mem_range ** as the comparator arguments. */
static int cmp_range(const void *a, const void *b) {
    const struct mem_range *x = *(const struct mem_range *const *)a;
    const struct mem_range *y = *(const struct mem_range *const *)b;
    if (x->start < y->start) return -1;
    if (x->start > y->start) return 1;
    if (x->end < y->end)     return -1;
    if (x->end > y->end)     return 1;
    return 0;
}

/* Sort a TAILQ list using an array and qsort */
void tailq_sort(struct ram_regions *list) {
    /* Count elements */
    size_t n = 0;
    struct mem_range *it;
    TAILQ_FOREACH(it, list, entries)
        n++;

    if (n <= 1)
        return; /* nothing to sort */

    /* Copy pointers to array */
    struct mem_range **arr = malloc(n * sizeof(*arr));
    if (!arr)
        return;

    size_t i = 0;
    TAILQ_FOREACH(it, list, entries)
        arr[i++] = it;

    /* Sort array of pointers */
    qsort(arr, n, sizeof(*arr), cmp_range);

    /* Rebuild TAILQ */
    TAILQ_INIT(list);
    for (i = 0; i < n; i++)
        TAILQ_INSERT_TAIL(list, arr[i], entries);

    free(arr);
}

static void range_merge_overlaps(struct ram_regions *list) {
    struct mem_range *cur = TAILQ_FIRST(list);

    while (cur != NULL) {
        struct mem_range *next = TAILQ_NEXT(cur, entries);

        while (next != NULL && cur->end >= next->start) {
            /* extend current interval if necessary */
            if (next->end > cur->end)
                cur->end = next->end;

            /* remove next from list */
            TAILQ_REMOVE(list, next, entries);
            struct mem_range *tmp = TAILQ_NEXT(next, entries);
            free(next);
            next = tmp; /* continue merging */
        }

        /* move cur to the next distinct interval */
        cur = next;
    }
}

static void range_subtract(struct lemon_ctx *ctx, struct ram_regions *ram, struct ram_regions *not_ram) {
    struct mem_range *g = TAILQ_FIRST(ram);
    struct mem_range *b = TAILQ_FIRST(not_ram);

    while (g) {
        unsigned long long cur_start = g->start;
        unsigned long long cur_end   = g->end;
        bool virtual = g->virtual;

        /* Skip not_ram ranges before current ram */
        while (b && b->end <= cur_start)
            b = TAILQ_NEXT(b, entries);

        struct mem_range *b_iter = b;
        while (b_iter && b_iter->start < cur_end) {
            if (b_iter->start > cur_start) {
                struct mem_range *n = range_new(cur_start, b_iter->start, virtual);
                if (n) TAILQ_INSERT_TAIL(&ctx->ram_regions, n, entries);
            }

            if (b_iter->end >= cur_end) {
                cur_start = cur_end;
                break;
            }

            cur_start = b_iter->end;
            b_iter = TAILQ_NEXT(b_iter, entries);
        }

        if (cur_start < cur_end) {
            struct mem_range *n = range_new(cur_start, cur_end, virtual);
            if (n) TAILQ_INSERT_TAIL(&ctx->ram_regions, n, entries);
        }

        g = TAILQ_NEXT(g, entries);
    }
}

/*
 * get_iomem_regions_user() - Parse /proc/iomem to extract "System RAM" regions
 * @ram_regions: Pointer to store the extracted RAM regions
 *
 * Opens /proc/iomem, searches for "System RAM" regions, and populates the provided
 * ram_regions struct with the start and end addresses of each region. The function
 * reallocates memory as needed to accommodate additional regions. 
 * Returns 0 on success, or an error code on failure.
 */
int get_iomem_regions_user(struct lemon_ctx *ctx, struct ram_regions *ram, struct ram_regions *not_ram) {
    FILE *fp;
    char line[256];
    uintptr_t start, end;
    int cap_ret;
    struct mem_range *range;
    int ret = 0;

    /* Check if we have CAP_SYS_ADMIN capability */
    if((cap_ret = check_capability(ctx, CAP_SYS_ADMIN)) <= 0) {
        ERR("LEMON does not have CAP_SYS_ADMIN to read /proc/iomem");
        return cap_ret;
    }

    /* Open the /proc/iomem and parse only "System RAM" regions */
    fp = fopen("/proc/iomem", "r");
    if (!fp)
    {
        ERRNO("Failed to open /proc/iomem");
        return errno;
    }

    /* Divide regions in RAM and not RAM ones, semi open intervals [start, end) */
    while (fgets(line, sizeof(line), fp))
    {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2)
        {
            /* Allocate new range element */
            if(!(range = (range_new(start, end + 1, false)))) {
                ERRNO("Failed to allocate memory for RAM ranges");
                ret = errno;
                goto cleanup;
            }

            if (strcasestr(line, "System RAM"))
                TAILQ_INSERT_TAIL(ram, range, entries);
            else 
                TAILQ_INSERT_TAIL(not_ram, range, entries);
        }
    }

    /* Filter ranges to have not overlapping ranges */
    tailq_sort(ram);
    tailq_sort(not_ram);
    range_merge_overlaps(ram);
    range_merge_overlaps(not_ram);

    cleanup:
        if(fclose(fp)) {        
            ERRNO("Fail to close /proc/iomem");
            return errno;
        }

    return ret;
}

static struct resource *next_resource_uspace(const struct lemon_ctx *ctx,
                                              struct resource *cur,
                                              struct resource *subtree_root,
                                              __u8 **data)
{
    int err;
    struct resource *p = cur;

    /* Go into children first */
    if (p->child) {
        if ((err = read_kernel_memory((uintptr_t)p->child, sizeof(struct resource), data))) {
            ERR("Error reading child struct resource at %p", p->child);
            return NULL;
        }
        return (struct resource *)*data;
    }

    /* Walk up until we find a sibling */
    while (!p->sibling && p->parent) {
        if (p->parent == subtree_root) /* BUG: (?) p->parent is a kernel-space pointer read from kernel memory, while subtree_root is &root, a user-space stack address*/
            return NULL;

        if ((err = read_kernel_memory((uintptr_t)p->parent, sizeof(struct resource), data))) {
            ERR("Error reading parent struct resource at %p", p->parent);
            return NULL;
        }
        p = (struct resource *)*data;
    }

    /* Follow sibling */
    if (!p->sibling)
        return NULL;

    if ((err = read_kernel_memory((uintptr_t)p->sibling, sizeof(struct resource), data))) {
        ERR("Error reading sibling struct resource at %p", p->sibling);
        return NULL;
    }
    return (struct resource *)*data;
}

/*
 * get_iomem_regions_kernel() - Parse struct resources directly in kernel to extract "System RAM" regions
 * @ram_regions: Pointer to store the extracted RAM regions
 *
 * Read struct resources from kernel, and populates the provided
 * ram_regions struct with the start and end addresses of each region. The function
 * reallocates memory as needed to accommodate additional regions. 
 * Returns 0 on success, or an error code on failure.
 */
int get_iomem_regions_kernel(struct lemon_ctx *ctx, struct ram_regions *ram, struct ram_regions *not_ram)
{
    __u8 *data = NULL;
    struct resource *res, root;
    struct resource *cur_kptr;          /* current kernel-space pointer */
    int err;
    struct mem_range *range;

    /* Read the root resource struct */
    if ((err = read_kernel_memory(ctx->iomem_resource, sizeof(struct resource), &data))) {
        ERR("Error reading root struct resource");
        return err;
    }
    memcpy(&root, data, sizeof(root));  /* save root for subtree boundary check */

    /* Start from root->child */
    if (!root.child)
        return 0;

    cur_kptr = root.child;
    if ((err = read_kernel_memory((uintptr_t)cur_kptr, sizeof(struct resource), &data))) {
        ERR("Error reading first child struct resource");
        return err;
    }
    res = (struct resource *)data;

    /* Walk the full tree: children + siblings, kernel-style */
    while (res) {
        if (!(range = range_new(res->start, res->end + 1, false))) {
                ERRNO("Failed to allocate memory for new ranges");
                return errno;
            }
        /* Check for System RAM */
        if (res->name && ((res->flags & SYSTEM_RAM_FLAGS) == SYSTEM_RAM_FLAGS)) {
            TAILQ_INSERT_TAIL(ram, range, entries);
        }
        else {
            TAILQ_INSERT_TAIL(not_ram, range, entries);
        }

        /* Advance to next node in the tree */
        struct resource cur_copy = *res;    /* copy before data buffer is overwritten */
        res = next_resource_uspace(ctx, &cur_copy, &root, &data);
    }

    /* Filter ranges to have non-overlapping ranges */
    tailq_sort(ram);
    tailq_sort(not_ram);
    range_merge_overlaps(ram);
    range_merge_overlaps(not_ram);

    return 0;
}

/* If the iomem_resource symbol is available access to it through eBPF bypassing CAP_SYS_ADMIN
* Otherwise use /proc/iomem which requires CAP_SYS_ADMIN.
*/
int parse_iomem(struct lemon_ctx *restrict ctx) {
    int status;
    struct ram_regions ram, not_ram;

    /* Init lists */
    TAILQ_INIT(&ram);
    TAILQ_INIT(&not_ram);
    
    if(ctx->iomem_resource && !ctx->opts.force_iomem_user) {
        status = get_iomem_regions_kernel(ctx, &ram, &not_ram);
    }
    else
        status = get_iomem_regions_user(ctx, &ram, &not_ram);

    
    /* For now we copy the entire System RAM regions */
    // range_subtract(&ctx->ram_regions, &ram, &not_ram);
    // range_list_free(&ram);
    memcpy(&ctx->ram_regions, &ram, sizeof(struct ram_regions));
    range_list_free(&not_ram);

    return status;
}
