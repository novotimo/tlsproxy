// A TCP sink for the benchmark backend. It accepts connections, discards or
// echoes whatever arrives, and closes only when the peer closes.
//
// Nothing in here times out. That is the whole point: an HTTP server used as
// the backend of a handshake-rate test holds every abandoned connection for
// client_header_timeout and then closes connections the proxy is still using,
// so the measurement ends up describing the backend.
//
// One process per worker, each with its own SO_REUSEPORT listener and epoll,
// so the kernel spreads accepts by 4-tuple hash.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_EVENTS 512
#define BUF_SIZE   65536

typedef struct {
    int    fd;
    char  *pending;             // allocated only when a write cannot complete
    size_t len;
    size_t off;
} conn_t;

static int  echo_mode;
static char rbuf[BUF_SIZE];

static void die(const char *what) { perror(what); _exit(1); }

static int make_listener(int port, int backlog) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd == -1)
        die("socket");

    int on = 1, off = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
        die("setsockopt SO_REUSEADDR");
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1)
        die("setsockopt SO_REUSEPORT");
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) == -1)
        die("setsockopt IPV6_V6ONLY");

    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_addr   = in6addr_any;
    a.sin6_port   = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == -1)
        die("bind");
    if (listen(fd, backlog) == -1)
        die("listen");
    return fd;
}

static void conn_close(int ep, conn_t *c) {
    epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    free(c->pending);
    free(c);
}

static int conn_arm(int ep, conn_t *c) {
    struct epoll_event ev;
    ev.events   = EPOLLET | EPOLLRDHUP | (c->pending ? EPOLLOUT : EPOLLIN);
    ev.data.ptr = c;
    return epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev);
}

// Returns 0 when the connection has been closed and must not be touched again.
static int conn_flush(int ep, conn_t *c) {
    while (c->off < c->len) {
        ssize_t w = write(c->fd, c->pending + c->off, c->len - c->off);
        if (w > 0) {
            c->off += (size_t)w;
            continue;
        }
        if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 1;
        if (w == -1 && errno == EINTR)
            continue;
        conn_close(ep, c);
        return 0;
    }
    free(c->pending);
    c->pending = NULL;
    c->len = c->off = 0;
    // Reading was suspended while a write was outstanding; resume it.
    if (conn_arm(ep, c) == -1) {
        conn_close(ep, c);
        return 0;
    }
    return 1;
}

static int conn_read(int ep, conn_t *c) {
    for (;;) {
        ssize_t r = read(c->fd, rbuf, sizeof(rbuf));
        if (r == 0) {                       // peer closed, and only then
            conn_close(ep, c);
            return 0;
        }
        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1;
            if (errno == EINTR)
                continue;
            conn_close(ep, c);
            return 0;
        }
        if (!echo_mode)
            continue;

        size_t sent = 0;
        while (sent < (size_t)r) {
            ssize_t w = write(c->fd, rbuf + sent, (size_t)r - sent);
            if (w > 0) {
                sent += (size_t)w;
                continue;
            }
            if (w == -1 && errno == EINTR)
                continue;
            if (w == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Hold the remainder and stop reading until it drains, so a
                // slow reader applies backpressure instead of growing a queue.
                c->len     = (size_t)r - sent;
                c->pending = malloc(c->len);
                if (!c->pending) {
                    conn_close(ep, c);
                    return 0;
                }
                memcpy(c->pending, rbuf + sent, c->len);
                c->off = 0;
                if (conn_arm(ep, c) == -1) {
                    conn_close(ep, c);
                    return 0;
                }
                return 1;
            }
            conn_close(ep, c);
            return 0;
        }
    }
}

static void accept_all(int ep, int lfd) {
    for (;;) {
        int fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            if (errno == EMFILE || errno == ENFILE || errno == ENOMEM)
                return;             // shed rather than spin; the peer retries
            return;
        }
        int on = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        conn_t *c = calloc(1, sizeof(*c));
        if (!c) {
            close(fd);
            return;
        }
        c->fd = fd;

        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLET | EPOLLRDHUP;
        ev.data.ptr = c;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) == -1) {
            close(fd);
            free(c);
            return;
        }
    }
}

static void worker(int port, int backlog) {
    int lfd = make_listener(port, backlog);
    int ep  = epoll_create1(EPOLL_CLOEXEC);
    if (ep == -1)
        die("epoll_create1");

    struct epoll_event ev;
    ev.events   = EPOLLIN;              // level-triggered, so accepts are fair
    ev.data.ptr = NULL;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev) == -1)
        die("epoll_ctl listener");

    struct epoll_event evs[MAX_EVENTS];
    for (;;) {
        int n = epoll_wait(ep, evs, MAX_EVENTS, -1);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            die("epoll_wait");
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].data.ptr == NULL) {
                accept_all(ep, lfd);
                continue;
            }
            conn_t  *c = evs[i].data.ptr;
            uint32_t e = evs[i].events;

            if ((e & EPOLLOUT) && !conn_flush(ep, c))
                continue;
            if ((e & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))
                && !conn_read(ep, c))
                continue;
        }
    }
}

int main(int argc, char **argv) {
    int port = 80, workers = 2, backlog = 65535, opt;

    while ((opt = getopt(argc, argv, "p:w:b:e")) != -1) {
        switch (opt) {
        case 'p': port    = atoi(optarg); break;
        case 'w': workers = atoi(optarg); break;
        case 'b': backlog = atoi(optarg); break;
        case 'e': echo_mode = 1;          break;
        default:
            fprintf(stderr,
                    "usage: %s [-p port] [-w workers] [-b backlog] [-e]\n",
                    argv[0]);
            return 2;
        }
    }
    if (port < 1 || port > 65535 || workers < 1 || workers > 256) {
        fprintf(stderr, "port must be 1-65535 and workers 1-256\n");
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("sink: port=%d workers=%d mode=%s\n",
           port, workers, echo_mode ? "echo" : "discard");

    for (int i = 1; i < workers; i++) {
        pid_t pid = fork();
        if (pid == -1)
            die("fork");
        if (pid == 0) {
            worker(port, backlog);
            _exit(0);
        }
    }
    worker(port, backlog);
    return 0;
}
