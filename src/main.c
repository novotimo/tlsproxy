#include "main.h"

#include <err.h>
#include <sys/epoll.h>

int main(int argc, char *argv[]) {
    printf("TLS Proxy starting\n");

    struct epoll_event events[TPX_MAX_EVENTS];

    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        err(EXIT_FAILURE, "Couldn't create epoll fd");

    connection_t *listener = tpx_create_listener(NULL, 9090);
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = listener;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->fd, &ev) == -1)
        err(EXIT_FAILURE, "epoll_ctl: listen_sock");

    int nfds;
    for (;;) {
        nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);
        for (size_t n=0; n < nfds; ++n)
            tpx_handle_all(events[n].data.ptr, epollfd, events[n].events);
    }
    
    return(EXIT_SUCCESS);
}
