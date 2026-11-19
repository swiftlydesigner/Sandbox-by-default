/* snoop_mem.c - attempt to read system memory.
 * Exit 0: attack succeeded (sandbox failed). Exit 2: access denied. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int try_read(const char *path)
{
    unsigned char buf[64];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "  open %s: %s\n", path, strerror(errno));
        return 0;
    }
    ssize_t n = pread(fd, buf, sizeof buf, 0);
    int saved = errno;
    close(fd);
    if (n > 0) {
        fprintf(stderr, "  READ %zd bytes from %s\n", n, path);
        return 1;
    }
    fprintf(stderr, "  pread %s: %s\n", path, n < 0 ? strerror(saved) : "EOF");
    return 0;
}

static int try_mmap_devmem(void)
{
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "  open /dev/mem: %s\n", strerror(errno));
        return 0;
    }
    void *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    int saved = errno;
    close(fd);
    if (p == MAP_FAILED) {
        fprintf(stderr, "  mmap /dev/mem: %s\n", strerror(saved));
        return 0;
    }
    fprintf(stderr, "  MMAP OK: /dev/mem\n");
    munmap(p, 4096);
    return 1;
}

int main(void)
{
    int breach = 0;

    breach |= try_read("/dev/mem");
    breach |= try_read("/dev/kmem");
    breach |= try_read("/proc/kcore");
    breach |= try_read("/proc/1/mem");
    breach |= try_mmap_devmem();

    if (breach) {
        fprintf(stderr, "BREACH: host memory readable\n");
        return 0;
    }
    fprintf(stderr, "denied: no host memory access\n");
    return 2;
}
