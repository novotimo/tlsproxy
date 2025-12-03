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

void debug_conn(connection_t *conn) {
    printf("Connection info (%p):\n", conn);
    if (conn->handle_accept)
        printf("\tThis is a listen socket\n");
    else
        printf("\tThis is a connected socket\n");
    printf("\tfd=%d\n", conn->fd);
//    printf("rw_bufs=%p\n", conn->rw_bufs);
    printf("\tread_idx=%d\n", conn->read_idx);
    printf("\twrite_idx=%d\n", conn->write_idx);
//    printf("peer_addr=...\n");
//    printf("ssl_ctx=%p\n", conn->ssl_ctx);
}

int tpx_bufs_empty(connection_t *conn) {
    if (tpx_empty(conn->rw_bufs))
        return 1;
    if (conn->rw_bufs->first == conn->rw_bufs->last &&
        conn->read_idx == conn->write_idx)
        return 1;
    return 0;
}

tpx_err_t tpx_handle_all(connection_t *conn, int epollfd, uint32_t events) {
    int ret = TPX_SUCCESS;
    // We want to handle writes first so that the queue doesn't
    // grow as big
    if (0 != (events | EPOLLOUT) && conn->handle_write)
        ret = (conn->handle_write)(conn);
    if (ret != TPX_SUCCESS)
        return ret;
    
    if (0 != (events | EPOLLIN) && conn->handle_read) {
        // We're a connected socket
        ret = (conn->handle_read)(conn);
        if (ret != TPX_SUCCESS)
            return ret;

    } else if (0 != (events | EPOLLIN) && conn->handle_accept) {
        // We're the listening socket
        connection_t *newconn = (conn->handle_accept)(conn);
        if (!newconn)
            return TPX_FAILURE;

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
        ev.data.ptr = newconn;

        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, newconn->fd, &ev) == -1)
            err(EXIT_FAILURE, "tpx_handle_all: epoll_ctl");
    }
    return ret;
}

void tpx_conn_close(connection_t *conn, int epollfd) {
    epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->fd, NULL);
    if (conn->handle_close)
        (conn->handle_close)(conn);
    free(conn);
}

tpx_err_t tpx_handle_read(connection_t *conn) {
    unsigned char *rdbuf = NULL;
    size_t buflen = 0;

    // Invariants
    assert(conn->write_idx < TPX_NET_BUFSIZE);
    assert(tpx_empty(conn->rw_bufs) == (conn->write_idx == -1));
    
    if (conn->write_idx == -1) {
        rdbuf = malloc(TPX_NET_BUFSIZE);
        buflen = TPX_NET_BUFSIZE;
        tpx_enqueue(conn->rw_bufs, rdbuf, buflen);
        conn->write_idx = 0;
    } else {
        switch (tpx_peek_last(conn->rw_bufs, &rdbuf, &buflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_read: The queue @ 0x%p is corrupted\n",
                    conn->rw_bufs);
            return TPX_FAILURE;
        case TPX_EMPTY:
            fprintf(stderr, "tpx_handle_read: The queue @ 0x%p is corrupted: "
                    "write_idx isn't -1 with an empty queue\n",
                    conn->rw_bufs);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(conn->write_idx < buflen);
        }
    }

    
    int nbytes = -1;
    while ((nbytes = read(conn->fd, rdbuf + conn->write_idx, buflen - conn->write_idx)) > 0) {
        assert(buflen >= nbytes);
        if (conn->write_idx + nbytes == buflen) {
            rdbuf = malloc(TPX_NET_BUFSIZE);
            buflen = TPX_NET_BUFSIZE;
            tpx_enqueue(conn->rw_bufs, rdbuf, buflen);
            conn->write_idx = 0;
        } else {
            conn->write_idx += nbytes;
        }
    }

    // Invariants
    assert(conn->write_idx < TPX_NET_BUFSIZE);
    assert(tpx_empty(conn->rw_bufs) == (conn->write_idx == -1));
    
    if (nbytes == -1 && errno != EAGAIN) {
        perror("tpx_handle_read");
        return TPX_CLOSED;
    }

    if (!tpx_bufs_empty(conn))
        return (conn->handle_write)(conn);
    return TPX_SUCCESS;
}

tpx_err_t tpx_handle_write(connection_t *conn) {
    if (tpx_bufs_empty(conn))
        return TPX_SUCCESS;

    unsigned char *wbuf = NULL;
    size_t wbuflen = 0;

    int nsent;
    size_t real_buflen = 0;
    for (;;) {
        // Invariants
        assert(conn->read_idx < TPX_NET_BUFSIZE);
        // If both indices are in the came chunk then read idx can't
        // be after write
        assert(!((conn->rw_bufs->first == conn->rw_bufs->last) &&
                 (conn->write_idx < conn->read_idx)));
    
        switch (tpx_peek(conn->rw_bufs, &wbuf, &wbuflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_write: The queue @ 0x%p is corrupted\n",
                    conn->rw_bufs);
            return TPX_FAILURE;
        case TPX_EMPTY:
            return TPX_SUCCESS;
        case TPX_SUCCESS:
        default:
            assert(wbuf);
            // Get only the part of the buf that's got data in it
            if (conn->rw_bufs->first == conn->rw_bufs->last)
                real_buflen = conn->write_idx;
            else
                real_buflen = wbuflen;
            
            while (real_buflen > conn->read_idx &&
                   (nsent = send(conn->fd, wbuf + conn->read_idx,
                                 real_buflen - conn->read_idx,
                                 // I'm not the biggest fan of SIGPIPE
                                 MSG_NOSIGNAL)) > 0) {
                conn->read_idx += nsent;
            }

            // Are we done with this chunk?
            if (conn->read_idx == wbuflen) {
                tpx_dequeue(conn->rw_bufs, NULL, NULL);
                free(wbuf);
                conn->read_idx = 0;
            } else if (conn->read_idx == real_buflen) {
                // This means wbuflen != real_buflen so we're at the
                // end of the chunk currently being written
                return TPX_SUCCESS;
            }
            
            if (nsent == -1 && errno == EAGAIN) {
                return TPX_SUCCESS;
            } else if (nsent == -1 && errno != EAGAIN) {
                perror("tpx_handle_write");
                return TPX_CLOSED;
            }
        }

        // Invariants
        assert(conn->read_idx < TPX_NET_BUFSIZE);
        // If both indices are in the came chunk then read idx can't
        // be after write
        assert(!((conn->rw_bufs->first == conn->rw_bufs->last) &&
                 (conn->write_idx < conn->read_idx)));
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

void tpx_handle_close(connection_t *conn) {
    assert(!conn->closed);
    
    close(conn->fd);
    unsigned char *buf;
    if (conn->rw_bufs) {
        while(!tpx_empty(conn->rw_bufs)) {
            
            tpx_dequeue(conn->rw_bufs, &buf, NULL);
            if (buf) free(buf);
        }
        free(conn->rw_bufs);
    }
    
    conn->closed = 1;
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
    if (lp == NULL) {
        freeaddrinfo(listen_addr);
        errx(EXIT_FAILURE, "Couldn't bind on any addresses");
    }

    freeaddrinfo(listen_addr);

    if (listen(lsock, SOMAXCONN) < 0)
        err(EXIT_FAILURE, "tpx_create_listener: listen");

    connection_t *conn = malloc(sizeof(connection_t));

    conn->fd = lsock;
    conn->rw_bufs = NULL;
    conn->read_idx = 0;
    conn->write_idx = -1;
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
    conn->read_idx = 0;
    conn->write_idx = -1;
    memcpy(&conn->peer_addr, addr, addrlen);
    conn->ssl_ctx = NULL;
    conn->handle_read = &tpx_handle_read;
    conn->handle_write = &tpx_handle_write;
    conn->handle_close = &tpx_handle_close;
    conn->closed = 0;
    
    return conn;
}
