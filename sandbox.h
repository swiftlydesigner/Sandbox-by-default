#ifndef SANDBOX_H
#define SANDBOX_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <sched.h>


#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_NAME "sandbox_demo"

#define kOK 0
#define kERROR -1

int setup_user_namespace(void);
int setup_mount_namespace(void);
int setup_pid_namespace(void);
int setup_net_namespace(void);

int cgroup_create(void);
int cgroup_apply_limits(void);

int install_seccomp(void);

int block_fs_escape(void); /* mount‑ns pre‑setup */
int block_net_traffic(void); /* net‑ns creation */
int block_mem_snoop(void); /* seccomp rule add */
int block_res_exhaust(void); /* cgroup limits */
int block_priv_syscalls(void); /* seccomp rule add */


void errExit(const char*);

#endif /* SANDBOX_H */

