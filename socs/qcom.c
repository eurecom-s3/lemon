#include <stdio.h>
#include <errno.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "../lemon.h"

/*
 * qcom.c - Qualcomm Android: locate vmemmap via mem_section, detect secure pages from struct page.
 */

extern int read_kernel_memory(const uintptr_t addr, const size_t size, unsigned char **restrict data);

/* Magic in page.private for secure buffers (see Qcom secure_buffer.c in vendor trees). */
#define SECURE_PAGE_MAGIC 0xEEEEEEEE

/* vmemmap base for pfn -> struct page (SPARSEMEM_VMEMMAP). */
static uintptr_t vmemmap;

/* sizeof(struct page) from vmlinux BTF. */
static size_t struct_page_size;

/* Byte offset of page.private in struct page (BTF). */
static int private_offset;

/* ilog2(page size) for PFN math. */
static unsigned int page_shift;

/*
 * btf_find_field_recursive() - Find byte offset of a named member, including anonymous nesting
 * @btf: Loaded vmlinux BTF.
 * @type_id: Starting struct/union type id.
 * @field_name: Member name to resolve.
 * @base_offset_bits: Accumulated bit offset from outer anonymous wrappers.
 *
 * Returns byte offset from struct start, or -1 if not found.
 */
static int btf_find_field_recursive(struct btf *btf,
                                     __u32 type_id,
                                     const char *field_name,
                                     __u32 base_offset_bits)
{
    const struct btf_type   *t = btf__type_by_id(btf, type_id);
    const struct btf_member *m;
    __u16 vlen;

    if (!t) return -1;

    /* Strip typedef/const/volatile wrappers. */
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

        if (name && name[0] != '\0') {
            if (strcmp(name, field_name) == 0)
                return (int)(member_bit_off / 8);
        } else {
            /* Anonymous struct/union member: search inside with accumulated offset. */
            const struct btf_type *mt = btf__type_by_id(btf, m->type);

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

/*
 * check_init_qualcomm() - Enable Qualcomm mode and compute vmemmap from mem_section[]
 * @ctx: Android + SoC strings, ram_regions, mem_section symbol, BTF/Core flags.
 *
 * Returns 0 if not applicable, 1 on success, or errno (e.g. EINVAL, ENOSYS) on failure.
 */
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

    /* Non-Qualcomm Android or non-Android: leave ctx->is_qualcomm false. */
    if(!ctx->is_android || (!strcasestr(ctx->soc_manufacturer, "Qualcomm") && !strcasestr(ctx->soc_manufacturer, "QTI"))) return 0;
    ctx->is_qualcomm = true;
    INFO("Device uses Qualcomm SoC");

    /* Needs BTF relocation and vmemmap-backed struct page layout. */
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
    if (!struct_type || !struct_type->size) { /* size is __u32; == 0 means missing BTF info. */
        ERR("Invalid sizeof(struct page)");
        ret = EINVAL;
        goto cleanup;
    }
    struct_page_size = struct_type->size;

    /* Locate page.private; the SECURE_PAGE_MAGIC check reads this field. */
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
    if (!struct_type || !struct_type->size) {
        ERR("Invalid sizeof(mem_section)");
        ret = EINVAL;
        goto cleanup;
    }
    mem_section_size = struct_type->size;

    /* section_mem_map encodes the vmemmap pointer ORed with flags; bit 0 is the present flag. */
    section_mem_map_offset = btf_find_field_recursive(vmlinux_btf, struct_id, "section_mem_map", 0);
    if(section_mem_map_offset < 0) {
        ERR("Invalid offset for section_mem_map field of struct mem_section");
        ret = EINVAL;
        goto cleanup;
    }

    /* mem_section is mem_section ** in the kernel image; dereference twice. */
    if(read_kernel_memory(ctx->mem_section, sizeof(uintptr_t), &data)) { /* mem_section ** */
        ERR("Failed to access mem_section array (symbol)");
        ret = EIO;
        goto cleanup;
    }

    if(read_kernel_memory(*(uintptr_t *)data, sizeof(uintptr_t), &data)) { /* mem_section * */
        ERR("Failed to access mem_section array (1st dereference)");
        ret = EIO;
        goto cleanup;
    }

    /*
     * Scan early mem_section[] rows; section_mem_map encodes vmemmap | flags.
     * PFN section size depends on page size (64K vs 4K kernels).
     */
    pfn_section_shift = getpagesize() == 65536 ? 29 : 27;
    if (TAILQ_EMPTY(&ctx->ram_regions)) {
        ERR("No RAM regions available for mem_section analysis");
        ret = ENODATA;
        goto cleanup;
    }
    min_section = ((TAILQ_FIRST(&ctx->ram_regions)->start) >> pfn_section_shift) + 2;  /* small safety margin */

    if(read_kernel_memory(*(uintptr_t *)data, min_section * mem_section_size, &data)) { /* mem_section[0..] */
        ERR("Failed to read mem_section array");
        ret = EIO;
        goto cleanup;
    }

    for(i=0; i < min_section; i++) {
        candidate = *(uintptr_t *)(data + i * mem_section_size + section_mem_map_offset);
        if(!(candidate & 1)) continue; /* Bit 0 clear: section not present. */

        vmemmap = candidate & 0xFFFFFFFFFFFFF000; /* Mask out flag bits; keep page-aligned base. */
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

/*
 * qualcomm_is_secure_page() - True if struct page.private holds SECURE_PAGE_MAGIC
 * @page_start: Physical base address of the page (dump granule aligned).
 *
 * On read failure logs and returns false (caller may attempt a normal memory read).
 */
bool qualcomm_is_secure_page(uintptr_t page_start) {
    unsigned long *private;
    uint8_t *data = NULL;
    const uintptr_t pfn = page_start >> page_shift;
    const uintptr_t addr = vmemmap + pfn * struct_page_size;
    
    if (read_kernel_memory(addr, struct_page_size, &data)) {
        ERR("Failed to read struct pages for page 0x%lx (0x%lx)", page_start, addr);
        return false;
    }
    private = (unsigned long *)(data + private_offset);

    return *private == SECURE_PAGE_MAGIC;
}
