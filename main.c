#include "sandbox.h"

int main(int argc, char *argv[]) {

    FILE *f = fopen("/proc/self/status","r");
    char line[256];
    while (fgets(line,sizeof(line),f)) {
        if (strncmp(line,"CapEff:",7)==0) {
            printf("%s",line);
            break;
        }
    }
    fclose(f);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/untrusted [args…]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Unshare namesapces
//    if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
//                CLONE_NEWNET | CLONE_NEWUTS) == -1) {
//        errExit("unshare");
//    }

    // Configure
//    if (setup_user_namespace() != kOK) {
//        errExit("user ns");
//    }
//
//    if (setup_mount_namespace() != kOK) {
//        errExit("mount ns");
//    }
//
//    if (setup_net_namespace() != kOK) {
//        errExit("net ns");
//    }

    if (cgroup_create() != kOK) {
        errExit("cgroup create");
    }

    if (cgroup_apply_limits() != kOK) {
        errExit("cgroup limits");
    }

    if (install_seccomp() != kOK) {
        errExit("seccomp");
    }

    // Harden rules
    block_fs_escape(); // Harden mount_ns [unused]
    block_net_traffic(); // Harden net_ns [unused]
    block_mem_snoop(); // Harden seccomp with memory snooping
    block_res_exhaust(); // Harden resource exhaustion rules [unused]
    block_priv_syscalls(); // Harden seccomp with priv sys calls

    // Fork to get PID 1 for child
    pid_t pid = fork();
    if (pid == -1) {
        puts("failed to fork main");
        errExit("fork");
    }

    if (pid == 0) {
        execv(argv[1], &argv[1]);
        puts("failed to execute binary");
        errExit("execv");
    }

    // Wait for child
    int st;
    if (waitpid(pid, &st, 0) == -1) {
        puts("failed to wait for child to exit (it DNE or died)");
        errExit("waitpid");
    }

    if (WIFSIGNALED(st)) {
        fprintf(stderr, "Sandboxed program killed by signal %d\n",
                WTERMSIG(st));
    } else if (WIFEXITED(st)) {
        printf("Sandboxed program exited with status %d\n",
               WEXITSTATUS(st));
    }

    // rm cgroup
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", CGROUP_ROOT, CGROUP_NAME);
    rmdir(path);

    return kOK;
}

