#include "../sandbox.h"

int setup_mount_namespace(void) {
    // make current mount tree private
    if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) == -1) {
        return kERROR;
    }

    // bind & mount as readonly
    if (mount("/", "/", "bind", MS_BIND | MS_REC, NULL) == -1) {
        return kERROR;
    }

    if (mount("/", "/", "remount", MS_BIND | MS_RDONLY | MS_REMOUNT, NULL) == -1) {
        return kERROR;
    }

    /* private /tmp (tmpfs) */
    if (mount("tmpfs", "/tmp", "tmpfs", 0,
              "size=64M,mode=1777") == -1) {
        return kERROR
    }

    return kOK;
}
