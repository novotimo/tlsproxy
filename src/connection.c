#include "connection.h"

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "errors.h"

void tpx_handle_all(connection_t *conn, int epollfd, uint32_t events) {
    // We want to handle writes first so that the queue doesn't
    // grow as big
    if (0 != (events | EPOLLOUT) && conn->handle_write)
        (conn->handle_write)(conn);
    
    // We're an accept socket
    if (0 != (events | EPOLLIN) && conn->handle_read) {
        (conn->handle_read)(conn);
    } else if (0 != (events | EPOLLIN) && conn->handle_accept) {
        connection_t *newconn = (conn->handle_accept)(conn);
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
        ev.data.ptr = newconn;

        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, newconn->fd, &ev) == -1)
            err(EXIT_FAILURE, "tpx_handle_all: epoll_ctl");
    }
}

void printq(queue_t *queue) {
    printf("Queue first: %p\n", queue->first);
    printf("Queue last: %p\n", queue->last);

    queue_elem_t *el;
    for (el = queue->first; el != NULL; el=el->next) {
        printf("Elem: %p %lu, next=%p\n", el->buf, el->buflen, el->next);
    }
}

void tpx_handle_read(connection_t *conn) {
    printf("tpx_handle_read\n");
    unsigned char *rdbuf = malloc(TPX_NET_BUFSIZE);
    printf("got rdbuf=%p\n",rdbuf);
    int nbytes = -1;
    while ((nbytes = read(conn->fd, rdbuf, TPX_NET_BUFSIZE)) > 0) {
        printf("got nbytes=%d\n",nbytes);
        assert(TPX_NET_BUFSIZE >= nbytes);
        printf("trying to enqueue this read buffer\n");
        printq(conn->rw_bufs);
        tpx_enqueue(conn->rw_bufs, rdbuf, nbytes);
        printf("enqueued this read buffer\n");
        printq(conn->rw_bufs);
        rdbuf = malloc(TPX_NET_BUFSIZE);
        printf("malloced the next rdbuf=%p\n", rdbuf);
    }
    printf("exited, got nbytes=%d, errno=%d\n",nbytes, errno);
    free(rdbuf);
    
    if (nbytes == -1 && errno != EAGAIN) {
        perror("tpx_handle_read");
        return;
    }

    if (!tpx_empty(conn->rw_bufs))
        (conn->handle_write)(conn);
    printf("tpx_handle_read exited\n");
}

void tpx_handle_write(connection_t *conn) {
    printf("tpx_handle_write\n");
    unsigned char *wbuf = NULL;
    size_t wbuflen = 0;

    int nsent;
    for (;;) {
        switch (tpx_peek(conn->rw_bufs, &wbuf, &wbuflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_write: The queue @ 0x%p is corrupted\n", conn->rw_bufs);
            return;
        case TPX_EMPTY:
            printf("tpx_handle_write: queue empty\n");
            return;
        case TPX_SUCCESS:
        default:
            while ((nsent = send(conn->fd, wbuf + conn->buf_index,
                                 wbuflen - conn->buf_index, 0)) > 0)
                conn->buf_index += nsent;

            // Are we done with this chunk?
            if (conn->buf_index == wbuflen) {
                tpx_dequeue(conn->rw_bufs, NULL, NULL);
                conn->buf_index = 0;
            }
            
            if (nsent == -1 && errno == EAGAIN) {
                printf("tpx_handle_write exiting: EAGAIN\n");
                return;
            } else if (nsent == -1 && errno != EAGAIN) {
                perror("tpx_handle_write");
                return;
            }
        }
    }
}

connection_t *tpx_handle_accept(connection_t *conn) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int conn_sock = accept(conn->fd, (struct sockaddr *) &addr,
                           &addrlen);
    if (conn_sock == -1) {
        perror("tpx_handle_accept");
        return NULL;
    }

    return tpx_create_accept(conn_sock, (struct sockaddr *)&addr,
                             addrlen);
}


connection_t *tpx_create_listener(const char *host,
                                  const unsigned short port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    char service[6];
    snprintf(service, sizeof(service), "%d", port);
    
    struct addrinfo *listen_addr, *lp;
    int error = getaddrinfo(host, service, &hints, &listen_addr);
    if (error != 0)
        errx(EXIT_FAILURE, "getaddrinfo for listener: %s",
             gai_strerror(error));

    int lsock = -1;
    int opt = 0;
    char h[NI_MAXHOST];
    for (lp = listen_addr; lp != NULL; lp = lp->ai_next) {
        lsock = socket(lp->ai_family, lp->ai_socktype,
                       lp->ai_protocol);
        if (lsock == -1) {
            perror("tpx_create_listener: socket");
            continue;
        }

        opt = 1;
        if (setsockopt(lsock, SOL_SOCKET,
                       SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
            err(EXIT_FAILURE, "tpx_create_listener: setsockopt (reuse)");
        opt = 0;
        if (lp->ai_family == AF_INET6
                && setsockopt(lsock, IPPROTO_IPV6,
                              IPV6_V6ONLY, &opt, sizeof(opt)))
            err(EXIT_FAILURE, "tpx_create_listener: setsockopt (ipv6)");

        if (bind(lsock, lp->ai_addr, lp->ai_addrlen) < 0) {
            perror("tpx_create_listener: bind");
        } else {
            break;
        }

        close(lsock);
    }
    if (lp == NULL)
        errx(EXIT_FAILURE, "Couldn't bind on any addresses");

    if (listen(lsock, SOMAXCONN) < 0)
        err(EXIT_FAILURE, "tpx_create_listener: listen");

    connection_t *conn = malloc(sizeof(connection_t));

    conn->fd = lsock;
    conn->rw_bufs = NULL;
    conn->buf_index = 0;
    conn->ssl_ctx = NULL;
    conn->handle_read = NULL;
    conn->handle_write = NULL;
    conn->handle_accept = &tpx_handle_accept;
    
    return conn;
}

connection_t *tpx_create_accept(int conn_sock, struct sockaddr *addr,
                                socklen_t addrlen) {

    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        perror("tpx_create_accept: fcntl(GETFL)");
        return NULL;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        perror("tpx_create_accept: fcntl(SETFL)");
        return NULL;
    }

    connection_t *conn = malloc(sizeof(connection_t));

    conn->fd = conn_sock;
    conn->rw_bufs = calloc(1, sizeof(queue_t));
    conn->buf_index = 0;
    memcpy(&conn->peer_addr, addr, addrlen);
    conn->peer_port = addrlen;
    conn->ssl_ctx = NULL;
    conn->handle_read = &tpx_handle_read;
    conn->handle_write = &tpx_handle_write;
    
    return conn;
}
