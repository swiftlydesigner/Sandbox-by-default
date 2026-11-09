#include "sandbox.h"

int block_mem_snoop(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (!ctx) {
        return kERROR;
    }

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS_ptrace, 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS_process_vm_readv, 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS_process_vm_writev, 0);

    return seccomp_load(ctx) ? -1 : (seccomp_release(ctx), 0);
}

