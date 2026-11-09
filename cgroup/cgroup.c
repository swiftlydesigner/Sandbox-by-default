#include "sandbox.h"

// Write to group file
static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        return kERROR;
    }

    if (write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf)) {
        close(fd);
        return kERROR;
    }

    close(fd);

    return kOK;
}

// Create group
int cgroup_create(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", CGROUP_ROOT, CGROUP_NAME);

    if (mkdir(path, 0755) && errno != EEXIST) {
        return kERROR;
    }

    snprintf(path, sizeof(path), "%s/%s/cgroup.procs",
             CGROUP_ROOT, CGROUP_NAME);

    return write_file(path, "%d\n", getpid());
}

// Set limits
int cgroup_apply_limits(void) {
    char path[256];

    snprintf(path, sizeof(path), "%s/%s/cpu.max", CGROUP_ROOT, CGROUP_NAME);

    if (write_file(path, "20000 100000\n") == -1) { // 20% utilization
        return kERROR;
    }

    snprintf(path, sizeof(path), "%s/%s/memory.max", CGROUP_ROOT, CGROUP_NAME);
    if (write_file(path, "67108864\n") == -1) { // 64 MB
        return kERROR;
    }

    snprintf(path, sizeof(path), "%s/%s/io.max", CGROUP_ROOT, CGROUP_NAME);
    if (write_file(path, "rbps=5242880 wbps=5242880\n") == -1) { // 5 MB/s
        return kERROR;
    }

    return kOK;
}

