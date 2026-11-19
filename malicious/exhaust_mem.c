/* exhaust_mem.c - allocate memory until OOM, with a safety cap.
 * Exit 0: cap or malloc failure reached without being stopped (sandbox failed). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_BYTES (1UL << 20)    /* 1 MiB */
#define CAP_MIB     16384UL        /* safety cap: 16 GiB */

int main(void)
{
    unsigned long allocated_mib = 0;

    for (;;) {
        if (allocated_mib >= CAP_MIB) {
            fprintf(stderr, "BREACH: reached %lu MiB cap without being stopped\n",
                    allocated_mib);
            return 0;
        }
        void *p = malloc(CHUNK_BYTES);
        if (p == NULL) {
            fprintf(stderr, "BREACH: malloc failed after %lu MiB (OOM reached)\n",
                    allocated_mib);
            return 0;
        }
        memset(p, 0xA5, CHUNK_BYTES);   /* touch pages so they are committed */
        allocated_mib++;
    }
}
