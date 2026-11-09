CC = gcc
CFLAGS = -Wall -O2 -D_FORTIFY_SOURCE=2
LDFLAGS = -lseccomp

SRC = main.c \
      block/fs_escape.c           namespace/mount_namespace.c \
	  block/mem_snoop.c           namespace/net_namespace.c \
	  block/network_block.c       namespace/pid_namespace.c \
	  block/priv_syscall.c        namespace/user_namespace.c \
	  block/resource_exhaust.c    seccomp/seccomp_filter.c \
	  cgroup/cgroup.c utility/io.c

OBJ = $(SRC:.c=.o)

sandbox: $(OBJ)
	     $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJ) sandbox

