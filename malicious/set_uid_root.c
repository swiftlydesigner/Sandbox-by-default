/* set_uid_root.c - attempt to become root.
 * Exit 0: privilege change succeeded (sandbox failed). Exit 2: denied. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int attempt(const char *name, int rc, int saved_errno)
{
    if (rc == 0) {
        fprintf(stderr, "  %s: SUCCEEDED\n", name);
        return 1;
    }
    fprintf(stderr, "  %s: %s\n", name, strerror(saved_errno));
    return 0;
}

int main(void)
{
    int breach = 0;
    int rc;

    fprintf(stderr, "uid=%d euid=%d gid=%d egid=%d\n",
            getuid(), geteuid(), getgid(), getegid());

    /* Starting as root means the sandbox never dropped privileges. */
    if (getuid() == 0 || geteuid() == 0) {
        fprintf(stderr, "BREACH: process already running as root\n");
        return 0;
    }

    rc = setuid(0);
    breach |= attempt("setuid(0)", rc, errno);
    rc = seteuid(0);
    breach |= attempt("seteuid(0)", rc, errno);
    rc = setreuid(0, 0);
    breach |= attempt("setreuid(0,0)", rc, errno);
    rc = setresuid(0, 0, 0);
    breach |= attempt("setresuid(0,0,0)", rc, errno);
    rc = setgid(0);
    breach |= attempt("setgid(0)", rc, errno);
    rc = setegid(0);
    breach |= attempt("setegid(0)", rc, errno);

    if (breach) {
        fprintf(stderr, "BREACH: obtained root privileges\n");
        return 0;
    }
    fprintf(stderr, "denied: cannot change to root\n");
    return 2;
}
