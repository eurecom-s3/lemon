#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <errno.h>
#include <sys/queue.h>

#include "lemon.h"

extern int check_capability(const cap_value_t cap);

static struct mem_range *range_new(unsigned long long start, unsigned long long end) {
    if (start >= end)
        return NULL;

    struct mem_range *n = malloc(sizeof(*n));
    if (!n)
        return NULL;

    n->start = start;
    n->end   = end;
    return n;
}


void range_list_free(struct ram_regions *list) {
    struct mem_range *it;
    while ((it = TAILQ_FIRST(list)) != NULL) {
        TAILQ_REMOVE(list, it, entries);
        free(it);
    }
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

static void range_subtract(struct ram_regions *ram_regions, struct ram_regions *ram, struct ram_regions *not_ram) {
    struct mem_range *g = TAILQ_FIRST(ram);
    struct mem_range *b = TAILQ_FIRST(not_ram);

    while (g) {
        unsigned long long cur_start = g->start;
        unsigned long long cur_end   = g->end;

        /* Skip not_ram ranges before current ram */
        while (b && b->end <= cur_start)
            b = TAILQ_NEXT(b, entries);

        struct mem_range *b_iter = b;
        while (b_iter && b_iter->start < cur_end) {
            if (b_iter->start > cur_start) {
                struct mem_range *n = range_new(cur_start, b_iter->start);
                if (n) TAILQ_INSERT_TAIL(ram_regions, n, entries);
            }

            if (b_iter->end >= cur_end) {
                cur_start = cur_end;
                break;
            }

            cur_start = b_iter->end;
            b_iter = TAILQ_NEXT(b_iter, entries);
        }

        if (cur_start < cur_end) {
            struct mem_range *n = range_new(cur_start, cur_end);
            if (n) TAILQ_INSERT_TAIL(ram_regions, n, entries);
        }

        g = TAILQ_NEXT(g, entries);
    }
}


static void range_print(struct ram_regions *list) {
    struct mem_range *it;
    TAILQ_FOREACH(it, list, entries)
        printf("  [0x%llx, 0x%llx)\n", it->start, it->end);
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
int get_iomem_regions_user(struct ram_regions *restrict ram_regions) {
    FILE *fp;
    char line[256];
    uintptr_t start, end;
    int cap_ret;
    struct ram_regions ram, not_ram;
    struct mem_range *range;

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

    /* Init lists */
    TAILQ_INIT(ram_regions);
    TAILQ_INIT(&ram);
    TAILQ_INIT(&not_ram);

    /* Divide regions in RAM and not RAM ones, semi open intervals [start, end) */
    while (fgets(line, sizeof(line), fp))
    {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2)
        {
            /* Allocate new range element */
            if(!(range = (range_new(start, end + 1)))) {
                range_list_free(ram_regions);
                range_list_free(&ram);
                range_list_free(&not_ram);
                
                perror("Failed to allocate memory for RAM ranges");
                return errno;
            }

            if (strcasestr(line, "System RAM"))
                TAILQ_INSERT_TAIL(&ram, range, entries);
            else if (strcasestr(line, "Reserved"))
                TAILQ_INSERT_TAIL(&not_ram, range, entries);
        }
    }

    if(fclose(fp)) {
        range_list_free(ram_regions);
        range_list_free(&ram);
        range_list_free(&not_ram);
        
        perror("Fail to close /proc/iomem");
        return errno;
    }

    /* Filter ranges to have not overlapping ranges of only valid RAM */
    tailq_sort(&ram);
    tailq_sort(&not_ram);
    range_merge_overlaps(&ram);
    range_merge_overlaps(&not_ram);

    range_subtract(ram_regions, &ram, &not_ram);

    range_print(ram_regions);

    /* Free temporary list */
    range_list_free(&ram);
    range_list_free(&not_ram);

    return 0;
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
// int get_iomem_regions_kernel(struct ram_regions *restrict ram_regions) {
//     int slot_availables;
//     __u8 *data = NULL;
//     struct resource *res, *next_res;
//     int err;

//     /* Initial RAM regions allocations */
//     ram_regions->num_regions = 0;
//     slot_availables = 8;

//     ram_regions->regions = (struct mem_range *)malloc(slot_availables * sizeof(struct mem_range));
//     if (!ram_regions->regions)
//     {
//         perror("Failed to allocate memory for RAM ranges");
//         return errno;
//     }
    
//     /* We follow the implementation of LiME considering only sibling leafs (level 1 only).
//      * Is it possible to have "System RAM" regions inside non System RAM regions? I don't think so. 
//      */

//     /* Obtain the address child of the root struct */
//     if((err = read_kernel_memory(iomem_resource, sizeof(struct resource), &data))) {
//         fprintf(stderr, "Error reading root struct resource");
//         return err;
//     }
//     res = ((struct resource *)data);
//     next_res = res->child;

//     /* Walk the sibling list */
//     while(next_res) {
//         if((err = read_kernel_memory((uintptr_t)next_res, sizeof(struct resource), &data))) {
//             fprintf(stderr, "Error reading sibling struct");
//             return err;
//         }
//         res = ((struct resource *)data);

//         /* Check if it is a "System RAM" region using flags instead of string (reduce memory copying from kernel to user) */
//         if(res->name && ((res->flags & SYSTEM_RAM_FLAGS) == SYSTEM_RAM_FLAGS)) {
//             /* If the array is full, reallocate to increase its size */
//             if (ram_regions->num_regions >= slot_availables)
//             {
//                 slot_availables *= 2;
//                 ram_regions->regions = 
//                     (struct mem_range *)realloc(ram_regions->regions, slot_availables * sizeof(struct mem_range));
//                 if (!ram_regions->regions)
//                 {
//                     perror("Failed to reallocate memory for RAM ranges");
//                     return errno;
//                 }
//             }

//             /* Save region start and end */
//             (ram_regions->regions)[ram_regions->num_regions].start = res->start;
//             (ram_regions->regions)[ram_regions->num_regions].end = res->end;
//             (ram_regions->num_regions)++;
//         }

//         /* Prepare for next iteration */
//         next_res = res->sibling;
//     }
//     return 0;
// }
