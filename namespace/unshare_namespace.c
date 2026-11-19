#include "../sandbox.h"

int unshare_ns(void) {
    int res = unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
            CLONE_NEWNET | CLONE_NEWUTS);

    return res == -1 ? kERROR : kOK;
}
