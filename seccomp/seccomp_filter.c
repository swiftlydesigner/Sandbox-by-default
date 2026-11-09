#include "sandbox.h"

int install_seccomp(void) {

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        return -1;
    }

    // Allow list - kill violating process
#define ALLOW(name) \
if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS_##name, 0) < 0) \
return -1

    ALLOW(read);
    ALLOW(write);
    ALLOW(open);
    ALLOW(close);
    ALLOW(fstat);
    ALLOW(lseek);
    ALLOW(mmap);
    ALLOW(munmap);
    ALLOW(brk);
    ALLOW(rt_sigaction);
    ALLOW(rt_sigprocmask);
    ALLOW(exit);
    ALLOW(exit_group);
    ALLOW(execve);
    ALLOW(arch_prctl);
    ALLOW(getpid);
    ALLOW(getuid);
    ALLOW(geteuid);
    ALLOW(getgid);
    ALLOW(getegid);
    ALLOW(set_robust_list);
    ALLOW(prlimit64);
    ALLOW(clock_gettime);
    ALLOW(nanosleep);
    ALLOW(getrandom);
    ALLOW(set_tid_address);
    ALLOW(setrlimit);

    /* The per‑vector modules will add extra deny rules */
    if (seccomp_load(ctx) < 0) {
        return kERROR;
    }

    seccomp_release(ctx);

    return kOK;
}

