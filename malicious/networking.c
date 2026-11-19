/* networking.c - attempt to reach the outside world (TCP, UDP DNS, name resolution).
 * Not expected to die. Exit 0: some attempt reached the outside (sandbox failed).
 * Exit 2: every attempt was denied or timed out. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PROBE_TIMEOUT_MS 2000
#define GLOBAL_TIMEOUT_S 20    /* must stay below the harness timeout */

/* Async-signal-safe watchdog: a hang is treated as "denied". */
static void on_alarm(int sig)
{
    static const char msg[] = "  watchdog expired: treating remaining probes as denied\n";
    (void)sig;
    ssize_t w = write(STDERR_FILENO, msg, sizeof msg - 1);
    (void)w;
    _exit(2);
}

static int tcp_probe(int family, const char *addr, uint16_t port, const char *label)
{
    struct sockaddr_storage ss;
    socklen_t slen;
    int fd, ok = 0;

    memset(&ss, 0, sizeof ss);
    if (family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        if (inet_pton(AF_INET, addr, &s4->sin_addr) != 1)
            return 0;
        slen = sizeof *s4;
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, addr, &s6->sin6_addr) != 1)
            return 0;
        slen = sizeof *s6;
    }

    fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "  %s: socket: %s\n", label, strerror(errno));
        return 0;
    }

    if (connect(fd, (struct sockaddr *)&ss, slen) == 0) {
        ok = 1;
    } else if (errno != EINPROGRESS) {
        fprintf(stderr, "  %s: %s\n", label, strerror(errno));
    } else {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, PROBE_TIMEOUT_MS) == 1) {
            int err = 0;
            socklen_t el = sizeof err;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
            if (err == 0)
                ok = 1;
            else
                fprintf(stderr, "  %s: %s\n", label, strerror(err));
        } else {
            fprintf(stderr, "  %s: no answer within %d ms\n", label, PROBE_TIMEOUT_MS);
        }
    }
    close(fd);

    if (ok)
        fprintf(stderr, "  %s: CONNECTED\n", label);
    return ok;
}

/* Sends a real DNS query for example.com/A and checks for a reply. */
static int dns_probe(const char *server, const char *label)
{
    unsigned char q[64];
    unsigned char r[512];
    struct sockaddr_in sa;
    size_t p = 0;
    int fd, ok = 0;

    /* DNS header: id, flags (recursion desired), qdcount=1, other counts=0 */
    q[p++] = 0x12; q[p++] = 0x34;
    q[p++] = 0x01; q[p++] = 0x00;
    q[p++] = 0x00; q[p++] = 0x01;
    q[p++] = 0x00; q[p++] = 0x00;
    q[p++] = 0x00; q[p++] = 0x00;
    q[p++] = 0x00; q[p++] = 0x00;
    /* QNAME: 7"example"3"com"0 */
    q[p++] = 7; memcpy(q + p, "example", 7); p += 7;
    q[p++] = 3; memcpy(q + p, "com", 3);     p += 3;
    q[p++] = 0;
    /* QTYPE=A, QCLASS=IN */
    q[p++] = 0x00; q[p++] = 0x01;
    q[p++] = 0x00; q[p++] = 0x01;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1)
        return 0;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "  %s: socket: %s\n", label, strerror(errno));
        return 0;
    }

    if (sendto(fd, q, p, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        fprintf(stderr, "  %s: sendto: %s\n", label, strerror(errno));
    } else {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, PROBE_TIMEOUT_MS) == 1) {
            ssize_t n = recv(fd, r, sizeof r, 0);
            if (n >= 12)
                ok = 1;
        }
        if (!ok)
            fprintf(stderr, "  %s: no DNS reply\n", label);
    }
    close(fd);

    if (ok)
        fprintf(stderr, "  %s: DNS REPLY RECEIVED\n", label);
    return ok;
}

static int resolve_probe(void)
{
    struct addrinfo hints, *res = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo("example.com", "80", &hints, &res);
    if (rc == 0) {
        fprintf(stderr, "  getaddrinfo(example.com): RESOLVED\n");
        freeaddrinfo(res);
        return 1;
    }
    fprintf(stderr, "  getaddrinfo(example.com): %s\n", gai_strerror(rc));
    return 0;
}

int main(void)
{
    struct sigaction sa;
    int breach = 0;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    alarm(GLOBAL_TIMEOUT_S);

    fprintf(stderr, "TCP:\n");
    breach |= tcp_probe(AF_INET,  "1.1.1.1",              443, "tcp 1.1.1.1:443");
    breach |= tcp_probe(AF_INET,  "8.8.8.8",               53, "tcp 8.8.8.8:53");
    breach |= tcp_probe(AF_INET,  "93.184.216.34",         80, "tcp 93.184.216.34:80");
    breach |= tcp_probe(AF_INET6, "2606:4700:4700::1111", 443, "tcp [2606:4700:4700::1111]:443");

    fprintf(stderr, "UDP DNS:\n");
    breach |= dns_probe("8.8.8.8", "udp dns 8.8.8.8");
    breach |= dns_probe("1.1.1.1", "udp dns 1.1.1.1");

    fprintf(stderr, "Name resolution:\n");
    breach |= resolve_probe();

    alarm(0);

    if (breach) {
        fprintf(stderr, "BREACH: reached the outside world\n");
        return 0;
    }
    fprintf(stderr, "denied: no outbound connectivity\n");
    return 2;
}
