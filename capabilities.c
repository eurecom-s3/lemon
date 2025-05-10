#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>

#include "lemon.h"

/*  Minimal capabilities required by LEMON:
 * 
 *  CAP_BPF          -> needed to load the eBPF components (on older kernels is included in CAP_SYS_ADMIN)
 *  CAP_PERFMON      -> needed to change RLIMIT_MEMLOCK, from libbpf, bypassable?, (on older kernel is included in CAP_SYS_ADMIN)
 *  CAP_SYSLOG       -> read addresses from /proc/kallsyms
 * 
 *  Capabilities needed in some cases
 *  
 *  CAP_SYS_ADMIN   ->  needed to change /proc/sys/kernel/kptr_restrict from 2 to 0 (not needed if set to 1 or 0), needed to access
 *                      /proc/iomem if CONFIG_KALLSYMS_ALL is not active and so iomem_resources is not available, needed on old kernels
 *  CAP_DAC_OVERRIDE -> needed to create a brand new dump file in the case the directory is not owned by the user running LEMON
 */


/*
 * check_capability() - Checks if the current process has a specific effective capability
 * @cap: The capability to check (e.g., CAP_SYS_PTRACE, CAP_NET_ADMIN)
 *
 * Retrieves the current process's capabilities using libcap, checks whether the given
 * capability is present in the effective set, and returns the result.
 * Returns 1 if the capability is set, 0 if not set, and a negative errno value on error.
 */
int check_capability(const cap_value_t cap) {
    cap_t caps;
    cap_flag_value_t cap_flag;
    int ret = 0;

    /* Get process capabilities */
    caps = cap_get_proc();
    if (caps == NULL) {
        perror("Fail to get current capabilities");
        return -errno;
    }


    /* Get effective capabilities */
    if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &cap_flag) == -1) {
        perror("Fail to get effective capabilities");
        ret = -errno;
        goto cleanup;
    }

    cleanup:
        if((ret = cap_free(caps))) {
            perror("Fail to free capabilities struct");
            return -errno;
        };

    if(!ret) ret = (cap_flag == CAP_SET);
    return ret;
}