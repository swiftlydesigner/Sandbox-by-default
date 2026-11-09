#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

int main(void) {
    struct addrinfo hints = {0}, *res;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo("example.com", "80", &hints, &res) != 0) {
        puts("DNS lookup failed (blocked or no network)");
        return 0;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock >= 0 && connect(sock, res->ai_addr, res->ai_addrlen) == 0) {
        puts("**Network access ALLOWED** - sandbox is not blocking connections");
        close(sock);
    } else {
        puts("**Network access BLOCKED** - connection failed as expected");
    }

    freeaddrinfo(res);
    return 0;
}
