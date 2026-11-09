#include "../sandbox.h"

int block_mem_snoop(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (!ctx) {
        puts("failed to get seccomp context for mem snoop");
        return kERROR;
    }

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_writev), 0);

    if (seccomp_load(ctx)) {
        puts("failed to get set rules for mem snoop");
        return kERROR;
    }

    seccomp_release(ctx);

    return kOK;
}
