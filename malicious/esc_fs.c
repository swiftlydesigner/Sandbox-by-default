/* esc_fs.c - attempt to escape the sandboxed filesystem and read host files.
 * Exit 0: attack succeeded (sandbox failed). Exit 2: access denied. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int try_read(const char *path)
{
    char buf[64];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "  open %s: %s\n", path, strerror(errno));
        return 0;
    }
    ssize_t n = read(fd, buf, sizeof buf);
    int saved = errno;
    close(fd);
    if (n > 0) {
        fprintf(stderr, "  READ %zd bytes from %s\n", n, path);
        return 1;
    }
    fprintf(stderr, "  read %s: %s\n", path, n < 0 ? strerror(saved) : "EOF");
    return 0;
}

int main(void)
{
    int breach = 0;
    char dir[] = "esc_XXXXXX";

    /* 1. Absolute paths to host files. */
    breach |= try_read("/etc/passwd");
    breach |= try_read("/etc/shadow");

    /* 2. Relative traversal far above any plausible sandbox root. */
    breach |= try_read("../../../../../../../../../../etc/passwd");

    /* 3. Classic chroot breakout: chroot into a subdirectory without chdir,
     *    climb with chdir(".."), then re-root at the real "/". */
    if (mkdtemp(dir) != NULL) {
        if (chroot(dir) == 0) {
            for (int i = 0; i < 256; i++)
                if (chdir("..") != 0)
                    break;
            if (chroot(".") == 0)
                breach |= try_read("/etc/passwd");
            else
                fprintf(stderr, "  chroot(\".\") after climb: %s\n", strerror(errno));
        } else {
            fprintf(stderr, "  chroot(%s): %s\n", dir, strerror(errno));
            rmdir(dir);
        }
    } else {
        fprintf(stderr, "  mkdtemp: %s\n", strerror(errno));
    }

    if (breach) {
        fprintf(stderr, "BREACH: host filesystem readable\n");
        return 0;
    }
    fprintf(stderr, "denied: no host filesystem access\n");
    return 2;
}
