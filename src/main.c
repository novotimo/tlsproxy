#include "main.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    printf("TLS Proxy starting\n");

    struct epoll_event events[TPX_MAX_EVENTS];

    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        err(EXIT_FAILURE, "Couldn't create epoll fd");

    int listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_sock == -1)
        err(EXIT_FAILURE, "socket");

    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
        err(EXIT_FAILURE, "setsockopt");
    opt = 0;
    if (setsockopt(listen_sock, IPPROTO_IPV6,
                   IPV6_V6ONLY, &opt, sizeof(opt)))
        err(EXIT_FAILURE, "setsockopt");

    struct sockaddr_in6 listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_addr = in6addr_any;
    listen_addr.sin6_port = htons(9090);

    if (bind(listen_sock, (struct sockaddr *)&listen_addr,
             sizeof(listen_addr)) < 0)
        err(EXIT_FAILURE, "bind");

    if (listen(listen_sock, SOMAXCONN) < 0)
        err(EXIT_FAILURE, "listen");
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1)
        err(EXIT_FAILURE, "epoll_ctl: listen_sock");

    int nfds, conn_sock;
    int sock_flags;
    for (;;) {
        nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);
        for (size_t n=0; n < nfds; ++n) {
            struct sockaddr_storage addr;
            socklen_t addrlen = sizeof(addr);
            memset(&addr, 0, sizeof(addr));
            if (events[n].data.fd == listen_sock) {
                conn_sock = accept(listen_sock, (struct sockaddr *) &addr,
                                   &addrlen);
                if (conn_sock == -1)
                    err(EXIT_FAILURE, "accept");
                sock_flags = fcntl(conn_sock, F_GETFL);
                if (sock_flags == -1)
                    err(EXIT_FAILURE, "fcntl: get flags");
                if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1)
                    err(EXIT_FAILURE, "fcntl: set flags");

                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = conn_sock;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1)
                    err(EXIT_FAILURE, "epoll_ctl: conn_sock");
            } else {
                echo_respond(events[n].data.fd);
            }
        }
    }
    
    return(EXIT_SUCCESS);
}

void echo_respond(int fd) {
    unsigned char buf[TPX_NET_BUFSIZE];
    int nread = 0;
    int nwritten = 0;
    while ((nread = read(fd, buf, sizeof(buf))) > 0) {
        nwritten = 0;
        printf("nread=%d\n", nread);
        
        do {
            int retcode = send(fd, buf+nwritten, nread-nwritten, 0);
            printf("retcode==%d\n", retcode);
            if (retcode == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // For now we just hope this never happens
                // I'm not equipped to flush the buffer yet
                return;
            }
            nwritten += retcode;
            printf("nwritten==%d\n", nwritten);
        } while (nwritten < nread);
    }
}
