#include "connection.h"

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "errors.h"

int tpx_outbuf_empty(connection_t *conn) {
    if (tpx_queue_empty(conn->out_bufq))
        return 1;
    if (conn->out_bufq->first == conn->out_bufq->last &&
        conn->out_bufq->read_idx == conn->out_bufq->write_idx)
        return 1;
    return 0;
}

int tpx_inbuf_empty(connection_t *conn) {
    if (tpx_queue_empty(conn->in_bufq))
        return 1;
    if (conn->in_bufq->first == conn->in_bufq->last &&
        conn->in_bufq->read_idx == conn->in_bufq->write_idx)
        return 1;
    return 0;
}

tpx_err_t tpx_conn_dispatch(connection_t *conn, int epollfd, uint32_t events,
                         SSL_CTX *ssl_ctx) {
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
        queue_t *bufq = tpx_queue_new();
        // We're the listening socket
        connection_t *newconn = (conn->handle_accept)(conn, ssl_ctx, bufq, bufq);
        if (!newconn) {
            tpx_queue_free(bufq);
            return TPX_FAILURE;
        }

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

tpx_err_t tpx_handle_connect(connection_t *conn) {
    return (conn->handle_process)(conn);
}

tpx_err_t tpx_handle_read(connection_t *conn) {
    unsigned char *rdbuf = NULL;
    size_t buflen = 0;

    // Invariants
    assert(conn->in_bufq->write_idx < TPX_NET_BUFSIZE);
    assert(tpx_queue_empty(conn->in_bufq) == (conn->in_bufq->write_idx == -1));

    if (conn->in_bufq->write_idx == -1) {
        // Add new chunk
        rdbuf = malloc(TPX_NET_BUFSIZE);
        buflen = TPX_NET_BUFSIZE;
        tpx_enqueue(conn->in_bufq, rdbuf, buflen);
        conn->in_bufq->write_idx = 0;
    } else {
        // Use existing chunk
        switch (tpx_queue_peek_last(conn->in_bufq, &rdbuf, &buflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_read: The queue @ 0x%p is corrupted\n",
                    conn->in_bufq);
            return TPX_FAILURE;
        case TPX_EMPTY:
            fprintf(stderr, "tpx_handle_read: The queue @ 0x%p is corrupted: "
                    "in_bufq->write_idx isn't -1 with an empty queue\n",
                    conn->in_bufq);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(conn->in_bufq->write_idx < buflen);
        }
    }

    
    
    int nbytes = -1;
    while (buflen > conn->in_bufq->write_idx &&
           ((nbytes = DO_READ(conn->ssl, conn->fd,
                              rdbuf + conn->in_bufq->write_idx,
                              buflen - conn->in_bufq->write_idx)) > 0)) {
        assert(buflen >= nbytes);
        if (conn->in_bufq->write_idx + nbytes == buflen) {
            rdbuf = malloc(TPX_NET_BUFSIZE);
            buflen = TPX_NET_BUFSIZE;
            tpx_enqueue(conn->in_bufq, rdbuf, buflen);
            conn->in_bufq->write_idx = 0;
        } else {
            conn->in_bufq->write_idx += nbytes;
        }
    }

    // Invariants
    assert(conn->in_bufq->write_idx < TPX_NET_BUFSIZE);
    assert(tpx_queue_empty(conn->in_bufq) == (conn->in_bufq->write_idx == -1));

    int ssl_err = 0;
    if (conn->ssl && (ssl_err = SSL_get_error(conn->ssl, nbytes))
                      != SSL_ERROR_WANT_READ) {
        ERR_print_errors_fp(stderr);
        return TPX_CLOSED;
    }

    if (nbytes == -1 && errno != EAGAIN) {
        perror("tpx_handle_read");
        return TPX_CLOSED;
    }

    if (conn->handle_process)
        return (conn->handle_process)(conn);

    return TPX_SUCCESS;
}

tpx_err_t tpx_handle_write(connection_t *conn) {
    if (tpx_outbuf_empty(conn))
        return TPX_SUCCESS;

    unsigned char *wbuf = NULL;
    size_t wbuflen = 0;

    int nsent;
    size_t real_buflen = 0;
    for (;;) {
        // Invariants
        assert(conn->out_bufq->read_idx < TPX_NET_BUFSIZE);
        // If both indices are in the came chunk then read idx can't
        // be after write
        assert(!((conn->out_bufq->first == conn->out_bufq->last) &&
                 (conn->out_bufq->write_idx < conn->out_bufq->read_idx)));
    
        switch (tpx_queue_peek(conn->out_bufq, &wbuf, &wbuflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_write: The queue @ 0x%p is corrupted\n",
                    conn->out_bufq);
            return TPX_FAILURE;
        case TPX_EMPTY:
            return TPX_SUCCESS;
        case TPX_SUCCESS:
        default:
            assert(wbuf);
            // Get only the part of the buf that's got data in it
            if (conn->out_bufq->first == conn->out_bufq->last)
                real_buflen = conn->out_bufq->write_idx;
            else
                real_buflen = wbuflen;
            
            while (real_buflen > conn->out_bufq->read_idx &&
                   (nsent = DO_SEND(conn->ssl, conn->fd,
                                    wbuf + conn->out_bufq->read_idx,
                                    real_buflen - conn->out_bufq->read_idx))
                   > 0) {
                conn->out_bufq->read_idx += nsent;
            }

            // Are we done with this chunk?
            if (conn->out_bufq->read_idx == wbuflen) {
                tpx_dequeue(conn->out_bufq, NULL, NULL);
                free(wbuf);
                conn->out_bufq->read_idx = 0;
            } else if (conn->out_bufq->read_idx == real_buflen) {
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
        assert(conn->out_bufq->read_idx < TPX_NET_BUFSIZE);
        // If both indices are in the came chunk then read idx can't
        // be after write
        assert(!((conn->out_bufq->first == conn->out_bufq->last) &&
                 (conn->out_bufq->write_idx < conn->out_bufq->read_idx)));
    }
}

tpx_err_t tpx_handle_process(connection_t *conn) {
    // Pretty much makes this an echo server.
    return tpx_handle_write(conn);
}

connection_t *tpx_handle_accept(connection_t *conn, SSL_CTX *ctx,
                                queue_t *in_bufq, queue_t *out_bufq) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int conn_sock = accept(conn->fd, (struct sockaddr *) &addr,
                           &addrlen);
    if (conn_sock == -1) {
        perror("tpx_handle_accept");
        return NULL;
    }

    return tpx_create_accept(conn_sock, (struct sockaddr *)&addr,
                             addrlen, ctx, in_bufq, out_bufq);
}

void tpx_handle_close(connection_t *conn) {
    assert(conn->state != CS_CLOSED);
    if (conn->ssl)
        SSL_free(conn->ssl);
    conn->ssl = NULL;
    
    close(conn->fd);
    conn->state = CS_CLOSED;
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
    conn->in_bufq = NULL;
    conn->out_bufq = NULL;
    conn->ssl = NULL;
    memset(&conn->peer_addr, 0, sizeof(struct sockaddr_storage));
    conn->peer_addrlen = 0;
    conn->handle_read = NULL;
    conn->handle_write = NULL;
    conn->handle_process = NULL;
    conn->handle_connect = NULL;
    conn->handle_accept = &tpx_handle_accept;
    conn->handle_close = NULL;
    conn->state = CS_LISTENING;
    conn->proxy = NULL;
    
    return conn;
}

connection_t *tpx_create_accept(int conn_sock, struct sockaddr *addr,
                                socklen_t addrlen, SSL_CTX *ctx,
                                queue_t *in_bufq, queue_t *out_bufq) {
    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        perror("tpx_create_accept: fcntl(GETFL)");
        return NULL;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        perror("tpx_create_accept: fcntl(SETFL)");
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Couldn't create SSL context\n");
        return NULL;
    }

    if (SSL_set_fd(ssl, conn_sock) != 1) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Couldn't assign socket to SSL context\n");
        return NULL;
    }

    SSL_set_accept_state(ssl);

    connection_t *conn = malloc(sizeof(connection_t));

    conn->fd = conn_sock;
    conn->in_bufq = in_bufq;
    conn->out_bufq = out_bufq;
    memcpy(&conn->peer_addr, addr, addrlen);
    conn->peer_addrlen = addrlen;
    conn->ssl = ssl;
    conn->handle_connect = NULL;
    conn->handle_read = &tpx_handle_read;
    conn->handle_write = &tpx_handle_write;
    conn->handle_process = &tpx_handle_process;
    conn->handle_connect = NULL;
    conn->handle_accept = NULL;
    conn->handle_close = &tpx_handle_close;
    conn->state = CS_CONNECTED;
    conn->proxy = NULL;

    return conn;
}


connection_t *tpx_create_connect(struct sockaddr *addr, socklen_t addrlen,
                                 queue_t *in_bufq, queue_t *out_bufq) {
    int conn_sock = socket(addr->sa_family, SOCK_STREAM, 0);
    if (conn_sock < 0) {
        perror("tpx_create_connect: socket");
        return NULL;
    }
    
    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        perror("tpx_create_connect: fcntl(GETFL)");
        return NULL;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        perror("tpx_create_connect: fcntl(SETFL)");
        return NULL;
    }

    if (connect(conn_sock, addr, addrlen) == -1 && errno != EINPROGRESS) {
        perror("tpx_create_connect: connect");
        return NULL;
    }

    connection_t *conn = malloc(sizeof(connection_t));

    conn->fd = conn_sock;
    conn->in_bufq = in_bufq;
    conn->out_bufq = out_bufq;
    memcpy(&conn->peer_addr, addr, addrlen);
    conn->peer_addrlen = addrlen;
    conn->ssl = NULL;
    conn->handle_connect = &tpx_handle_connect;
    conn->handle_read = &tpx_handle_read;
    conn->handle_write = &tpx_handle_write;
    conn->handle_process = &tpx_handle_process;
    conn->handle_close = &tpx_handle_close;
    conn->state = CS_CONNECTING;
    conn->proxy = NULL;
    
    return conn;
}

tpx_err_t tpx_conn_shutdown(connection_t *conn) {
    if (!conn->ssl)
        return TPX_FAILURE;
    
    int ret = SSL_shutdown(conn->ssl);
    if (ret == 1) {
        conn->state = CS_DONE;
        return TPX_SUCCESS;
    } else if (ret < 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "tpx_conn_shutdown\n");
        conn->state = CS_DONE;
        return TPX_FAILURE;
    }
    return TPX_AGAIN;
}
