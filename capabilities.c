#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <string.h>

#include "lemon.h"

/*
 * capabilities.c - Effective capability checks via libcap (ctx->capabilities from cap_get_proc).
 *
 * Typical needs:
 *   CAP_BPF / CAP_SYS_ADMIN - load eBPF (older kernels fold BPF into SYS_ADMIN).
 *   CAP_PERFMON / CAP_SYS_ADMIN - raise RLIMIT_MEMLOCK for libbpf.
 *   CAP_SYSLOG - read symbol addresses from /proc/kallsyms when restricted.
 *   CAP_SYS_ADMIN - relax kptr_restrict, read /proc/iomem if iomem_resource is missing.
 *   CAP_DAC_OVERRIDE - create dump files in directories not owned by the caller.
 */

/*
 * check_capability() - Test one capability in the effective set
 * @ctx: Must have ctx->capabilities initialized (cap_get_proc in collect_system_info).
 * @cap: Linux capability constant (e.g. CAP_SYS_ADMIN).
 *
 * Returns 1 if set, 0 if unset, or an errno value (> 1) if cap_get_flag fails.
 */
int check_capability(const struct lemon_ctx *restrict ctx, cap_value_t cap) {
    cap_flag_value_t cap_flag;

    /* Get effective capabilities */
    if (cap_get_flag(ctx->capabilities, cap, CAP_EFFECTIVE, &cap_flag) == -1) {
        RETURN_ERRNO("Fail to get effective capabilities");
    }

    return(cap_flag == CAP_SET);
}
