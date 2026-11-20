/* exhaust_cpu.c - fork bomb with a safety cap.
 * Exit 0: cap reached (sandbox did not stop the bomb). Exit 2: fork refused. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FORKS 15000L

struct shared {
    long count;
    int  hit_cap;
};

int main(void)
{
    struct shared *s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
//    pid_t root = getpid();

    for (;;) {
        if (__atomic_add_fetch(&s->count, 1, __ATOMIC_SEQ_CST) > MAX_FORKS) {
            __atomic_store_n(&s->hit_cap, 1, __ATOMIC_SEQ_CST);
            break;
        }
        pid_t p = fork();
        if (p < 0)
            break;          /* fork refused: sandbox contained us */
        if (p == 0)
            continue;       /* child keeps bombing */
    }

    while (wait(NULL) > 0)
        ;                   /* reap our children */

//    if (getpid() != root)
//        _exit(0);           /* descendants exit quietly; root reports */

    if (__atomic_load_n(&s->hit_cap, __ATOMIC_SEQ_CST)) {
        fprintf(stderr, "BREACH: %ld forks without being stopped\n", MAX_FORKS);
        return 0;
    }
    fprintf(stderr, "denied: fork refused, bomb contained\n");
    return 2;
}
