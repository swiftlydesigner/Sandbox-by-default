#include "../sandbox.h"

int install_seccomp(void) {

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        return kERROR;
    }

    // Allow list - kill violating process
    if (
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0) < 0) |
         ((seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0) < 0)
        ) {
        return kERROR;
    }

    /* The per‑vector modules will add extra deny rules */
    if (seccomp_load(ctx) < 0) {
        return kERROR;
    }

    seccomp_release(ctx);

    return kOK;
}
