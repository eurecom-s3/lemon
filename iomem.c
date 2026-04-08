#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <errno.h>
#include <sys/queue.h>

#include "lemon.h"

/*
 * iomem.c - RAM region lists: range helpers, /proc/iomem parsing, and kernel resource tree walks.
 */

/* Mirror of struct resource in include/linux/ioport.h (layout stable since Linux 4.6). */
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

/*
 * range_new() - Allocate one mem_range for half-open [start, end)
 * @start: First byte of the range (inclusive).
 * @end: Byte past the last byte (exclusive); must be greater than @start.
 * @virtual: Whether dump_region() should use virtual addresses for this range.
 *
 * Returns NULL on invalid bounds or malloc failure (errno set by malloc on OOM).
 */
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

/*
 * range_list_free() - Remove and free every mem_range on a TAILQ head
 * @list: Queue head (may be NULL).
 */
void range_list_free(struct ram_regions *list) {
    struct mem_range *it, *tmp;
    if(!list) return;

    TAILQ_FOREACH_SAFE(it, list, entries, tmp) {
        /* TAILQ_FOREACH_SAFE saves next before REMOVE. */
        TAILQ_REMOVE(list, it, entries);
        free(it);
    }

    TAILQ_INIT(list);
}

/*
 * cmp_range() - qsort comparator for struct mem_range * (sort by start, then end).
 */
static int cmp_range(const void *a, const void *b) {
    const struct mem_range *x = *(const struct mem_range *const *)a;
    const struct mem_range *y = *(const struct mem_range *const *)b;
    if (x->start < y->start) return -1;
    if (x->start > y->start) return 1;
    if (x->end < y->end)     return -1;
    if (x->end > y->end)     return 1;
    return 0;
}

/*
 * tailq_sort() - Stable logical order: copy pointers to an array, qsort, rebuild TAILQ
 * @list: In/out list (reinitialized then repopulated).
 *
 * On malloc failure, leaves the list unsorted and logs a warning.
 */
void tailq_sort(struct ram_regions *list) {
    /* Count nodes for array allocation. */
    size_t n = 0;
    struct mem_range *it;
    TAILQ_FOREACH(it, list, entries)
        n++;

    if (n <= 1)
        return; /* nothing to sort */

    /* Copy pointers to array */
    struct mem_range **arr = malloc(n * sizeof(*arr));
    if (!arr) {
        WARN("Failed to allocate memory for sorting %zu ranges", n);
        return;
    }

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

/*
 * range_merge_overlaps() - Merge adjacent or overlapping half-open intervals in place
 * @list: Sorted list (caller runs tailq_sort first).
 */
static void range_merge_overlaps(struct ram_regions *list) {
    struct mem_range *cur = TAILQ_FIRST(list);

    while (cur != NULL) {
        struct mem_range *next = TAILQ_NEXT(cur, entries);

        while (next != NULL && cur->end >= next->start) {
            /* Extend cur to cover next; drop the redundant node. */
            if (next->end > cur->end)
                cur->end = next->end;

            /* Save successor before unlinking next (TAILQ_REMOVE invalidates next's links). */
            struct mem_range *tmp = TAILQ_NEXT(next, entries);
            TAILQ_REMOVE(list, next, entries);
            free(next);
            next = tmp; /* continue merging */
        }

        /* move cur to the next distinct interval */
        cur = next;
    }
}

/*
 * range_subtract() - Subtract not_ram holes from ram into ctx->ram_regions (unused today)
 * @ctx: Destination queue for resulting gaps.
 * @ram: System RAM intervals.
 * @not_ram: Reserved / non-RAM intervals to carve out.
 * 
 *  This function is not currently in use. Filtering for annidated reserved regions seems to be usefull
 *  to prevent crashes in other SoCs such as Mediatek and Exynos in Samsung phones.
 */
static __attribute__((unused)) void range_subtract(struct lemon_ctx *ctx, struct ram_regions *ram, struct ram_regions *not_ram) {
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
 * get_iomem_regions_user() - Parse /proc/iomem into RAM vs non-RAM TAILQs
 * @ctx: Capability checks only.
 * @ram: Out: ranges whose lines contain "System RAM".
 * @not_ram: Out: all other parsed ranges (for future subtraction).
 *
 * Requires CAP_SYS_ADMIN. Uses half-open [start, end+1) after sscanf end inclusive.
 * Returns 0 on success, or an error code on failure.
 */
int get_iomem_regions_user(struct lemon_ctx *ctx, struct ram_regions *ram, struct ram_regions *not_ram) {
    FILE *fp;
    char line[256];
    uintptr_t start, end;
    int cap_ret;
    struct mem_range *range;
    int ret = 0;

    /* /proc/iomem exposes physical ranges only with CAP_SYS_ADMIN (without iomem_resource). */
    if((cap_ret = check_capability(ctx, CAP_SYS_ADMIN)) != 1) {
        ERR("LEMON does not have CAP_SYS_ADMIN to read /proc/iomem");
        return (cap_ret > 1) ? cap_ret : EPERM;
    }

    fp = fopen("/proc/iomem", "r");
    if (!fp)
    {
        RETURN_ERRNO("Failed to open /proc/iomem");
    }

    /* Parse all address ranges; end from the file is inclusive, convert to exclusive. */
    while (fgets(line, sizeof(line), fp))
    {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2)
        {
            if(!(range = (range_new(start, end + 1, false)))) {
                int saved_errno = errno;
                if (saved_errno)
                    ERRNO("Failed to allocate memory for RAM ranges");
                else
                    ERR("Invalid memory range in /proc/iomem: %lx-%lx", start, end);
                ret = saved_errno ? saved_errno : EINVAL;
                goto cleanup;
            }

            if (strcasestr(line, "System RAM"))
                TAILQ_INSERT_TAIL(ram, range, entries);
            else 
                TAILQ_INSERT_TAIL(not_ram, range, entries);
        }
    }

    /* Normalize ordering and merge overlaps within each class. */
    tailq_sort(ram);
    tailq_sort(not_ram);
    range_merge_overlaps(ram);
    range_merge_overlaps(not_ram);

    cleanup:
        if(fclose(fp)) {
            if (!ret) ret = errno;
            ERRNO("Fail to close /proc/iomem");
        }

    return ret;
}

/*
 * next_resource_uspace() - Kernel resource tree preorder successor using eBPF reads
 * @ctx: iomem_resource root pointer for end-of-walk detection.
 * @cur: Last visited node (user copy; pointers are kernel addresses).
 * @data: In/out: mmap buffer from read_kernel_memory (overwritten each read).
 * @err_out: Set to read_kernel_memory errno on failure; unchanged on normal NULL return.
 *
 * Returns the next struct resource image in *data, or NULL at end of walk / error.
 */
static struct resource *next_resource_uspace(const struct lemon_ctx *ctx,
                                              struct resource *cur,
                                              __u8 **data,
                                              int *err_out)
{
    int err;
    struct resource *p = cur;

    /* Depth-first: child first if present. */
    if (p->child) {
        if ((err = read_kernel_memory((uintptr_t)p->child, sizeof(struct resource), data))) {
            ERR("Error reading child struct resource at %p", p->child);
            *err_out = err;
            return NULL;
        }
        return (struct resource *)*data;
    }

    /* Climb to parent until a sibling exists or we hit the iomem root sentinel. */
    while (!p->sibling && p->parent) {
        if ((uintptr_t)p->parent == ctx->iomem_resource)
            return NULL;

        if ((err = read_kernel_memory((uintptr_t)p->parent, sizeof(struct resource), data))) {
            ERR("Error reading parent struct resource at %p", p->parent);
            *err_out = err;
            return NULL;
        }
        p = (struct resource *)*data;
    }

    /* Follow sibling */
    if (!p->sibling)
        return NULL;

    if ((err = read_kernel_memory((uintptr_t)p->sibling, sizeof(struct resource), data))) {
        ERR("Error reading sibling struct resource at %p", p->sibling);
        *err_out = err;
        return NULL;
    }
    return (struct resource *)*data;
}

/*
 * get_iomem_regions_kernel() - Walk struct resource under iomem_resource via eBPF reads
 * @ctx: Must have ctx->iomem_resource from kallsyms.
 * @ram: Out: SYSTEM_RAM|BUSY regions.
 * @not_ram: Out: other resource nodes under the tree.
 *
 * Returns 0 on success, or an error code if the tree cannot be read completely.
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
    memcpy(&root, data, sizeof(root));  /* Local copy: preserves child pointer before data is reused. */

    /* No child nodes: resource tree is empty for this root. */
    if (!root.child)
        return 0;

    cur_kptr = root.child;
    if ((err = read_kernel_memory((uintptr_t)cur_kptr, sizeof(struct resource), &data))) {
        ERR("Error reading first child struct resource");
        return err;
    }
    res = (struct resource *)data;

    /* Linearize the resource tree; walk_err catches mid-walk read_kernel_memory failures. */
    int walk_err = 0;
    while (res) {
        if (!(range = range_new(res->start, res->end + 1, false))) {
            int saved_errno = errno;
            if (saved_errno)
                ERRNO("Failed to allocate memory for new ranges");
            else
                ERR("Invalid memory range from kernel resource: %llx-%llx", res->start, res->end);
            return saved_errno ? saved_errno : EINVAL;
        }
        /* Check for System RAM */
        if (res->name && ((res->flags & SYSTEM_RAM_FLAGS) == SYSTEM_RAM_FLAGS)) {
            TAILQ_INSERT_TAIL(ram, range, entries);
        }
        else {
            TAILQ_INSERT_TAIL(not_ram, range, entries);
        }

        /* Copy node fields: next read overwrites *data backing res. */
        struct resource cur_copy = *res;
        res = next_resource_uspace(ctx, &cur_copy, &data, &walk_err);
    }

    if (walk_err)
        return walk_err;

    /* Same post-processing as the /proc/iomem path. */
    tailq_sort(ram);
    tailq_sort(not_ram);
    range_merge_overlaps(ram);
    range_merge_overlaps(not_ram);

    return 0;
}

/*
 * parse_iomem() - Fill ctx->ram_regions from kernel tree or /proc/iomem
 * @ctx: Uses iomem_resource and force_iomem_user to choose path.
 *
 * Moves the local `ram` head into ctx and fixes the list back-pointer.
 * Returns status from get_iomem_regions_* (0 on success).
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

    /*
     * Move local `ram` head into ctx->ram_regions by value copy, then fix the
     * back-pointer of the first node so the head remains self-consistent.
     * range_subtract() (commented out above) would be used here to carve out
     * reserved regions; kept for future use.
     */
    ctx->ram_regions = ram;
    if (TAILQ_EMPTY(&ctx->ram_regions))
        TAILQ_INIT(&ctx->ram_regions);
    else
        TAILQ_FIRST(&ctx->ram_regions)->entries.tqe_prev = &ctx->ram_regions.tqh_first;
    range_list_free(&not_ram);

    return status;
}
