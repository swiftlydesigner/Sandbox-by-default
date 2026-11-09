#include "../sandbox.h"

static int write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");

    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return kERROR;
    }

    if (fputs(text, f) == EOF || fclose(f) != 0) {
        fprintf(stderr, "write %s: %s\n", path, strerror(errno));
        return kERROR;
    }

    return kOK;
}

int setup_user_namespace(void) {
    char map[64];
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER) == -1) {
        perror("unshare(CLONE_NEWUSER)");
        return kERROR;
    }

    if (access("/proc/self/setgroups", F_OK) == 0) {
        if (write_file("/proc/self/setgroups", "deny\n") == -1) {
            perror("setgroups");
            exit(1);
        }
    }

    char str[256];
    snprintf(str, sizeof(str), "0 %d 1\n", getuid());
    if (write_file("/proc/self/uid_map", str) == -1) {
        perror("uid_map");
        exit(1);
    }

    snprintf(str, sizeof(str), "0 %d 1\n", getgid());
    if (write_file("/proc/self/gid_map", str) == -1) {
        perror("gid_map");
        exit(1);
    }

    return kOK;
}
