#include <stdio.h>
#include <errno.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <math.h>

#include "../lemon.h"

extern int read_kernel_memory(const uintptr_t addr, const size_t size, unsigned char **restrict data);

// as defined in kernel_platform/msm-kernel/drivers/soc/qcom/secure_buffer.c from Samsung Qualcomm source
#define SECURE_PAGE_MAGIC 0xEEEEEEEE

// Defined in arch/arm64/include/asm/pgtable.h
uintptr_t vmemmap;

/* sizeof(struct page) from BTF */
size_t struct_page_size;

/* Offset of unsigned long private in struct page */
int private_offset;

/* Page shift */
unsigned int page_shift;

static int btf_find_field_recursive(struct btf *btf,
                                     __u32 type_id,
                                     const char *field_name,
                                     __u32 base_offset_bits)
{
    const struct btf_type   *t = btf__type_by_id(btf, type_id);
    const struct btf_member *m;
    __u16 vlen;

    if (!t) return -1;

    // Resolv modifiers
    while (btf_is_mod(t) || btf_is_typedef(t)) {
        t = btf__type_by_id(btf, t->type);
        if (!t) return -1;
    }

    if (!btf_is_struct(t) && !btf_is_union(t))
        return -1;

    m    = btf_members(t);
    vlen = btf_vlen(t);

    for (__u16 i = 0; i < vlen; i++, m++) {
        const char *name = btf__name_by_offset(btf, m->name_off);

        __u32 member_bit_off = base_offset_bits;
        if (btf_kflag(t))
            member_bit_off += BTF_MEMBER_BIT_OFFSET(m->offset);
        else
            member_bit_off += m->offset;

        // Match diretto
        if (name && name[0] != '\0') {
            if (strcmp(name, field_name) == 0)
                return (int)(member_bit_off / 8);
        } else {
            // Anonymous field recursive!
            const struct btf_type *mt = btf__type_by_id(btf, m->type);
            
            // Resolve modifiers
            while (mt && (btf_is_mod(mt) || btf_is_typedef(mt)))
                mt = btf__type_by_id(btf, mt->type);

            if (mt && (btf_is_struct(mt) || btf_is_union(mt))) {
                int found = btf_find_field_recursive(btf, m->type,
                                                     field_name,
                                                     member_bit_off);
                if (found >= 0)
                    return found;
            }
        }
    }

    return -1;
}

/* Return 0 if not qualcomm, 1 if qualcomm ok, positive errno (> 1) on error */
int check_init_qualcomm(struct lemon_ctx *restrict ctx) {

    struct btf *vmlinux_btf;
    const struct btf_type *struct_type;
    int struct_id;
    int offset = -1;
    int section_mem_map_offset = -1;
    uint8_t *data = NULL;
    int i, min_section, pfn_section_shift;
    size_t mem_section_size;
    uintptr_t candidate;
    int ret = 1;

    page_shift = __builtin_ctz(getpagesize());

    /* Check if the system is Android and based on a Qualcomm SoC */
    if(!ctx->is_android || (!strcasestr(ctx->soc_manufacturer, "Qualcomm") && !strcasestr(ctx->soc_manufacturer, "QTI"))) return 0;
    ctx->is_qualcomm = true;
    INFO("Device use Qualcomm SoC");

    /* We support only CO-RE binaries and CONFIG_SPARSEMEM_VMEMMAP configurations */
    if(!ctx->is_core_supported || ctx->sparsemem_vmap_config != 'y') {
        ERR("Unsupported Qualcomm Kernel configuration. We support only CO-RE binaries and kernels with CONFIG_SPARSEMEM_VMEMMAP enabled");
        return ENOSYS;
    }

    /* Huge page is incompatible with the quirks */
    if(ctx->opts.use_huge_pages) {
        ERR("Huge page option is not usable on Qualcomm SoCs");
        return EINVAL;
    }

    /* We need the address of mem_section */
    if(!ctx->mem_section) {
        ERR("struct mem_section array not found.");
        return EINVAL;
    }

    /* Retrieve the struct page size from BTF symbols */
    vmlinux_btf = btf__load_vmlinux_btf();
    if (!vmlinux_btf) {
        ERR("Fail to load vmlinux BTF");
        return ENOENT;
    }

    struct_id = btf__find_by_name_kind(vmlinux_btf, "page", BTF_KIND_STRUCT);
    if(struct_id < 0) {
        ERR("struct page not present in BTF");
        ret = EINVAL;
        goto cleanup;
    }

    struct_type = btf__type_by_id(vmlinux_btf, struct_id);
    if (!struct_type || !struct_type->size) {
        ERR("Invalid sizeof(struct page)");
        ret = EINVAL;
        goto cleanup;
    }
    struct_page_size = struct_type->size;

    /* And now the offset of "unsigned long private" field */
    offset = btf_find_field_recursive(vmlinux_btf, struct_id, "private", 0);
    if(offset < 0) {
        ERR("Invalid offset for private field of struct page");
        ret = EINVAL;
        goto cleanup;
    }
    private_offset = offset;

    /* Now look for section_mem_map in mem_section */
    struct_id = btf__find_by_name_kind(vmlinux_btf, "mem_section", BTF_KIND_STRUCT);
    if(struct_id < 0) {
        ERR("struct mem_section not present in BTF");
        ret = EINVAL;
        goto cleanup;
    }

    struct_type = btf__type_by_id(vmlinux_btf, struct_id);
    if (!struct_type || struct_type->size <= 0) {
        ERR("Invalid sizeof(mem_section)");
        ret = EINVAL;
        goto cleanup;
    }
    mem_section_size = struct_type->size;

    section_mem_map_offset = btf_find_field_recursive(vmlinux_btf, struct_id, "section_mem_map", 0);
    if(section_mem_map_offset < 0) {
        ERR("Invalid offset for section_mem_map field of struct mem_section");
        ret = EINVAL;
        goto cleanup;
    }

    /* We read the double array mem_section */
    if(read_kernel_memory(ctx->mem_section, sizeof(uintptr_t), &data)) { /* mem_section ** address*/
        ERR("Failed to access mem_section array (symbol)");
        ret = EIO;
        goto cleanup;
    }

    if(read_kernel_memory(*(uintptr_t *)data, sizeof(uintptr_t), &data)) { /* mem_section * address */
        ERR("Failed to access mem_section array (1st dereference)");
        ret = EIO;
        goto cleanup;
    }

    /* mem_sections are associated to real System RAM regions and have inserted in order, so we have to test at least a sufficent
       number of section to identify the vmemmap base
    */

    pfn_section_shift = getpagesize() == 65536 ? 29 : 27;
    min_section = ((TAILQ_FIRST(&ctx->ram_regions)->start) >> pfn_section_shift) + 2; /* We add two more */

    /* Read the array */
    if(read_kernel_memory(*(uintptr_t *)data, min_section * mem_section_size, &data)) { /* mem_section[0] address */
        ERR("Failed to read mem_section array");
        ret = EIO;
        goto cleanup;
    }

    for(i=0; i < min_section; i++) {
        candidate = *(uintptr_t *)(data + i * mem_section_size + section_mem_map_offset);
        if(!(candidate & 1)) continue;

        vmemmap = candidate & 0xFFFFFFFFFFFFF000;
        break;
    }
    if(!vmemmap) {
        ERR("vmemmap not found");
        ret = EINVAL;
        goto cleanup;
    }

    DBG("vmemmap 0x%lx", vmemmap);

    cleanup:
        btf__free(vmlinux_btf);

    return ret;
}


bool qualcomm_is_secure_page(uintptr_t page_start) {
    unsigned long *private;
    uint8_t *data = NULL;
    const uintptr_t pfn = page_start >> page_shift;
    const uintptr_t addr = vmemmap + pfn * struct_page_size;
    
    if (read_kernel_memory(addr, struct_page_size, &data)) {
        ERR("Failed to read struct pages for page 0x%lx (0x%lx)", page_start, addr);
        return false;
    };
    private = (unsigned long *)(data + private_offset);

    return *private == SECURE_PAGE_MAGIC;
}
