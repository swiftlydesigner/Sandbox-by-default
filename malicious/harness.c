/* sandbox_test.c - runs each test under the sandbox and checks the outcome.
 * Usage: ./sandbox_test <sandbox> [sandbox args...]
 *        ./sandbox_test none    (run tests unsandboxed to confirm they detect a breach)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_SEC 30
#define MAX_ARGS    64

struct test {
    const char *name;
    const char *binary;
    const char *goal;
    int must_die;       /* 1: expected to be killed; 0: expected to survive and be denied */
};

static const struct test tests[] = {
    {"snoop_mem",    "./snoop_mem",    "read host memory (/dev/mem, /dev/kmem, /proc/kcore, /proc/1/mem)", 1},
    {"esc_fs",       "./esc_fs",       "escape the sandboxed filesystem and read host files",              1},
    {"set_uid_root", "./set_uid_root", "change uid/gid to root",                                           1},
    {"exhaust_cpu",  "./exhaust_cpu",  "fork bomb",                                                        1},
    {"exhaust_mem",  "./exhaust_mem",  "allocate memory until out of memory",                              1},
    {"networking",   "./networking",   "reach the outside world (TCP, UDP DNS, name resolution)",          0},
};
#define NTESTS (sizeof tests / sizeof tests[0])

enum verdict { PASS, WARN, FAIL, ERROR };
static const char *verdict_str[] = { "PASS", "WARN", "FAIL", "ERROR" };

static void kill_group(pid_t pgid)
{
    kill(-pgid, SIGKILL);   /* also cleans up anything the test left behind */
}

static enum verdict run_test(const struct test *t, int argc, char **argv,
                             char *detail, size_t len)
{
    int use_sandbox = strcmp(argv[1], "none") != 0;
    pid_t pid;
    int status = 0, timed_out = 0;
    time_t start;

    if (access(t->binary, X_OK) != 0) {
        snprintf(detail, len, "cannot execute %s: %s", t->binary, strerror(errno));
        return ERROR;
    }

    pid = fork();
    if (pid < 0) {
        snprintf(detail, len, "fork: %s", strerror(errno));
        return ERROR;
    }

    if (pid == 0) {
        char *args[MAX_ARGS];
        int n = 0;

        setpgid(0, 0);
        if (use_sandbox)
            for (int i = 1; i < argc && n < MAX_ARGS - 2; i++)
                args[n++] = argv[i];
        args[n++] = (char *)t->binary;
        args[n] = NULL;
        execvp(args[0], args);
        _exit(127);
    }

    setpgid(pid, pid);      /* avoid a race with the child's own setpgid */
    start = time(NULL);

    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            break;
        if (r < 0 && errno != EINTR) {
            snprintf(detail, len, "waitpid: %s", strerror(errno));
            kill_group(pid);
            return ERROR;
        }
        if (time(NULL) - start >= TIMEOUT_SEC) {
            timed_out = 1;
            kill_group(pid);
            waitpid(pid, &status, 0);
            break;
        }
        struct timespec ts = { 0, 100 * 1000 * 1000L };
        nanosleep(&ts, NULL);
    }
    kill_group(pid);

    if (timed_out) {
        snprintf(detail, len, "still running after %d s; sandbox did not stop it", TIMEOUT_SEC);
        return FAIL;
    }

    if (t->must_die) {
        if (WIFSIGNALED(status)) {
            snprintf(detail, len, "killed by signal %d (%s)",
                     WTERMSIG(status), strsignal(WTERMSIG(status)));
            return PASS;
        }
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 0) {
                snprintf(detail, len, "ran to completion; the attack succeeded");
                return FAIL;
            }
            if (code == 127) {
                snprintf(detail, len, "could not execute the sandbox or test binary");
                return ERROR;
            }
            if (code == 2) {
                snprintf(detail, len, "attack was denied, but the process was not terminated");
                return WARN;
            }
            snprintf(detail, len, "exited with code %d", code);
            return WARN;
        }
    } else {
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 0) {
                snprintf(detail, len, "connection to the outside world succeeded");
                return FAIL;
            }
            if (code == 2) {
                snprintf(detail, len, "all outbound attempts denied; process survived as expected");
                return PASS;
            }
            if (code == 127) {
                snprintf(detail, len, "could not execute the sandbox or test binary");
                return ERROR;
            }
            snprintf(detail, len, "exited with code %d", code);
            return WARN;
        }
        if (WIFSIGNALED(status)) {
            snprintf(detail, len, "killed by signal %d (%s); expected to survive",
                     WTERMSIG(status), strsignal(WTERMSIG(status)));
            return WARN;
        }
    }

    snprintf(detail, len, "unexpected wait status %d", status);
    return ERROR;
}

int main(int argc, char **argv)
{
    int failures = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <sandbox|none> [sandbox args...]\n", argv[0]);
        return 64;
    }

    for (size_t i = 0; i < NTESTS; i++) {
        char detail[256];
        enum verdict v = run_test(&tests[i], argc, argv, detail, sizeof detail);

        if (v == FAIL || v == ERROR)
            failures++;
        printf("[%s] %-13s %s\n", verdict_str[v], tests[i].name, detail);
        printf("       goal: %s\n", tests[i].goal);
    }

    printf("\n%zu test(s), %d failure(s)\n", NTESTS, failures);
    return failures ? 1 : 0;
}
