#include "../sandbox.h"

int setup_user_namespace(void) {
    FILE *f = fopen("/proc/self/uid_map", "w");

    if (!f) {
        puts("failed to open uid_map");
        return kERROR;
    }

    fprintf(f, "0 %d 1\n", getuid());
    fclose(f);

    f = fopen("/proc/self/setgroups", "w");

    if (f) {
        puts("failed to open setgrups");
        fprintf(f, "deny\n");
        fclose(f);
    }

    return kOK;
}
