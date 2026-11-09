#include "../sandbox.h"

int setup_user_namespace(void) {
    FILE *f = fopen("/proc/self/uid_map", "w");

    if (!f) {
        return kERROR;
    }

    fprintf(f, "0 %d 1\n", getuid());
    fclose(f);

    f = fopen("/proc/self/setgroups", "w");

    if (f) {
        fprintf(f, "deny\n");
        fclose(f);
    }

    return kOK;
}
