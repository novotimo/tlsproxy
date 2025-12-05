#include "proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "errors.h"
#include "event.h"
#include "queue.h"

int create_connect(proxy_t *proxy);
tpx_err_t proxy_handle_connect(proxy_t *proxy);


proxy_t *create_proxy(int accepted_fd, listen_t *listen, SSL *ssl,
                      struct sockaddr const* server_addr,
                      socklen_t server_addrlen) {
    proxy_t *proxy = malloc(sizeof(proxy_t));
    if (!proxy) {
        perror("create_proxy: malloc");
        return NULL;
    }

    proxy->event_id = EV_PROXY;
    proxy->c2s = queue_new();
    proxy->s2c = queue_new();
    proxy->client_fd = accepted_fd;
    memcpy(&proxy->server_addr, server_addr, server_addrlen);
    proxy->server_addrlen = server_addrlen;
    proxy->ssl = ssl;
    proxy->state = PS_CLIENT_CONNECTED;

    proxy->serv_fd = create_connect(proxy);
    tpx_err_t ret = proxy_handle_connect(proxy);
    if (ret == TPX_SUCCESS)
        proxy->state = PS_READY;
    else if (ret == TPX_AGAIN)
        proxy->state = PS_SERVER_CONNECTING;
    else {
        close(proxy->serv_fd);
        proxy->serv_fd = -1;

        queue_free(proxy->c2s);
        queue_free(proxy->s2c);

        // fd hasn't been added to epoll yet, and SSL will be freed outside
        free(proxy);
        
        fprintf(stderr, "create_proxy: connecting socket");
        proxy = NULL;
    }

    return proxy;
}

int create_connect(proxy_t *proxy) {
    int conn_sock = socket(proxy->server_addr.ss_family, SOCK_STREAM, 0);
    if (conn_sock < 0) {
        perror("create_connect: socket");
        return -1;
    }
    
    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        perror("create_connect: fcntl(GETFL)");
        return -1;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        perror("create_connect: fcntl(SETFL)");
        return -1;
    }
    return conn_sock;
}

tpx_err_t proxy_handle_connect(proxy_t *proxy) {
    assert(proxy->state == PS_CLIENT_CONNECTED ||
           proxy->state == PS_SERVER_CONNECTING);
    int retcode = connect(proxy->serv_fd,
                          (struct sockaddr *)&proxy->server_addr,
                          proxy->server_addrlen);
    if (retcode == -1 && errno != EINPROGRESS) {
        perror("proxy_handle_connect: connect");
        return TPX_FAILURE;
    } else if (retcode == -1 && errno == EINPROGRESS) {
        return TPX_AGAIN;
    } else {
        return TPX_SUCCESS;
    }
}

tpx_err_t proxy_add_to_epoll(proxy_t *proxy, int epollfd) {
    proxy_t *serv_proxy = proxy;
    // That's right, we're tagging the proxy pointer to see whether it's
    // a client or server event.
    proxy_t *client_proxy = (proxy_t *)((uintptr_t)proxy | 0x1);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = serv_proxy;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serv_proxy->serv_fd, &ev) == -1) {
        perror("Couldn't add server socket to epoll");
        return TPX_FAILURE;
    }
    
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = client_proxy;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serv_proxy->client_fd, &ev) == -1) {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, serv_proxy->serv_fd, NULL);
        perror("Couldn't add client socket to epoll");
        return TPX_FAILURE;
    }
    return TPX_SUCCESS;
}

void proxy_close(proxy_t *proxy, int epollfd) {
    if (proxy->state == PS_CLIENT_DISCONNECTED) {
        if (proxy->ssl)
            SSL_free(proxy->ssl);
        proxy->ssl = NULL;
    } else if (proxy->state == PS_SERVER_DISCONNECTED) {
        // If the shutdown isn't done yet
        if (SSL_shutdown(proxy->ssl) == 0)
            return;
        SSL_free(proxy->ssl);
    }
    
    if (epollfd != -1 && proxy->serv_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, proxy->serv_fd, NULL) == -1) {
            perror("proxy_close: epoll_ctl(serv)");
        }
    } if (proxy->client_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, proxy->client_fd, NULL) == -1) {
            perror("proxy_close: epoll_ctl(client)");
        }
    }

    queue_free(proxy->c2s);
    queue_free(proxy->s2c);
    
    if (proxy->serv_fd != -1)
        close(proxy->serv_fd);
    if (proxy->client_fd != -1)
        close(proxy->client_fd);
    free(proxy);
}

void handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                  void *ssl_ctx, uint8_t tag) {
    tpx_err_t ret = TPX_SUCCESS;

    switch (proxy->state) {
    case PS_CLIENT_CONNECTED:
    case PS_SERVER_CONNECTING:
        if (0 == (tag & 1)) {
            ret = proxy_handle_connect(proxy);
            if (ret == TPX_AGAIN)
                proxy->state = PS_SERVER_CONNECTING;
            else if (ret == TPX_SUCCESS)
                proxy->state = PS_READY;
            else if (ret == TPX_FAILURE)
                proxy_close(proxy, epollfd);
            return;
        }
    case PS_READY:
        // We want to handle writes first so that the queue doesn't
        // grow as big
        // TODO: Remember to handle closed connections here
        if (0 != (events | EPOLLOUT))
            ret = proxy_handle_write(proxy, tag);

        if (ret != TPX_SUCCESS) {
            if (0 != (tag & 1))
                proxy->state = PS_CLIENT_DISCONNECTED;
            else
                proxy->state = PS_SERVER_DISCONNECTED;
            break;
        }
    
        if (0 != (events | EPOLLIN))
            ret = proxy_handle_read(proxy, tag);
        
        if (ret != TPX_SUCCESS) {
            if (0 != (tag & 1))
                proxy->state = PS_CLIENT_DISCONNECTED;
            else
                proxy->state = PS_SERVER_DISCONNECTED;
            break;
        }
        return;
    default:
        break;
    }
    if (proxy->state == PS_SERVER_DISCONNECTED ||
        proxy->state == PS_CLIENT_DISCONNECTED) {
        proxy_close(proxy, epollfd);
    }
}

tpx_err_t proxy_handle_read(proxy_t *proxy, int is_client) {
    unsigned char *rdbuf = NULL;
    size_t buflen = 0;

    bufq_t *in_bufq, *out_bufq;
    int fd;
    if (is_client) {
        in_bufq = proxy->c2s;
        out_bufq = proxy->s2c;
        // Not actually used, but makes things clearer
        fd = proxy->client_fd;
    } else {
        in_bufq = proxy->s2c;
        out_bufq = proxy->c2s;
        fd = proxy->serv_fd;
    }

    // Invariants
    assert(in_bufq->write_idx < TPX_NET_BUFSIZE);
    assert(queue_empty(in_bufq) == (in_bufq->write_idx == -1));

    if (in_bufq->write_idx == -1) {
        // Add new chunk
        rdbuf = malloc(TPX_NET_BUFSIZE);
        buflen = TPX_NET_BUFSIZE;
        enqueue(in_bufq, rdbuf, buflen);
        in_bufq->write_idx = 0;
    } else {
        // Use existing chunk
        switch (queue_peek_last(in_bufq, &rdbuf, &buflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_read: The queue @ 0x%p is corrupted\n",
                    in_bufq);
            return TPX_FAILURE;
        case TPX_EMPTY:
            fprintf(stderr, "tpx_handle_read: The queue @ 0x%p is corrupted: "
                    "in_bufq->write_idx isn't -1 with an empty queue\n",
                    in_bufq);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(in_bufq->write_idx < buflen);
        }
    }

    
    
    int nbytes = -1;
    while (buflen > in_bufq->write_idx &&
           ((nbytes = DO_READ(proxy->ssl, fd,
                              rdbuf + in_bufq->write_idx,
                              buflen - in_bufq->write_idx)) > 0)) {
        assert(buflen >= nbytes);
        if (in_bufq->write_idx + nbytes == buflen) {
            rdbuf = malloc(TPX_NET_BUFSIZE);
            buflen = TPX_NET_BUFSIZE;
            enqueue(in_bufq, rdbuf, buflen);
            in_bufq->write_idx = 0;
        } else {
            in_bufq->write_idx += nbytes;
        }
    }

    // Invariants
    assert(in_bufq->write_idx < TPX_NET_BUFSIZE);
    assert(queue_empty(in_bufq) == (in_bufq->write_idx == -1));

    if (is_client && (SSL_get_error(proxy->ssl, nbytes)
                      != SSL_ERROR_WANT_READ)) {
        ERR_print_errors_fp(stderr);
        return TPX_CLOSED;
    }

    if (nbytes == -1 && errno != EAGAIN) {
        perror("tpx_handle_read");
        return TPX_CLOSED;
    }

    return proxy_process_data(proxy, is_client);
}

tpx_err_t proxy_process_data(proxy_t *proxy, int is_client) {
    return proxy_handle_write(proxy, !is_client);
}

int outbuf_empty(proxy_t *proxy, int is_client) {
    if (is_client && queue_empty(proxy->s2c))
        return 1;
    if (!is_client && queue_empty(proxy->c2s))
        return 1;
    if (is_client && proxy->s2c->first == proxy->s2c->last
        && proxy->s2c->read_idx == proxy->s2c->write_idx)
        return 1;
    if (!is_client && proxy->c2s->first == proxy->c2s->last
        && proxy->c2s->read_idx == proxy->c2s->write_idx)
        return 1;
    return 0;
}

tpx_err_t proxy_handle_write(proxy_t *proxy, int is_client) {
    if (outbuf_empty(proxy, is_client))
        return TPX_SUCCESS;

    unsigned char *wbuf = NULL;
    size_t wbuflen = 0;

    bufq_t *in_bufq, *out_bufq;
    int fd;
    if (is_client) {
        in_bufq = proxy->c2s;
        out_bufq = proxy->s2c;
        // Not actually used, but makes things clearer
        fd = proxy->client_fd;
    } else {
        in_bufq = proxy->s2c;
        out_bufq = proxy->c2s;
        fd = proxy->serv_fd;
    }
    
    int nsent;
    size_t real_buflen = 0;
    for (;;) {
        // Invariants
        assert(out_bufq->read_idx < TPX_NET_BUFSIZE);
        // If both indices are in the came chunk then read idx can't
        // be after write
        assert(!((out_bufq->first == out_bufq->last) &&
                 (out_bufq->write_idx < out_bufq->read_idx)));
    
        switch (queue_peek(out_bufq, &wbuf, &wbuflen)) {
        case TPX_FAILURE:
            fprintf(stderr, "tpx_handle_write: The queue @ 0x%p is corrupted\n",
                    out_bufq);
            return TPX_FAILURE;
        case TPX_EMPTY:
            return TPX_SUCCESS;
        case TPX_SUCCESS:
        default:
            assert(wbuf);
            // Get only the part of the buf that's got data in it
            if (out_bufq->first == out_bufq->last)
                real_buflen = out_bufq->write_idx;
            else
                real_buflen = wbuflen;
            
            while (real_buflen > out_bufq->read_idx &&
                   (nsent = DO_SEND(proxy->ssl, fd,
                                    wbuf + out_bufq->read_idx,
                                    real_buflen - out_bufq->read_idx))
                   > 0) {
                out_bufq->read_idx += nsent;
            }

            // Are we done with this chunk?
            if (out_bufq->read_idx == wbuflen) {
                dequeue(out_bufq, NULL, NULL);
                free(wbuf);
                out_bufq->read_idx = 0;
            } else if (out_bufq->read_idx == real_buflen) {
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
        assert(out_bufq->read_idx < TPX_NET_BUFSIZE);
        // If both indices are in the came chunk then read idx can't
        // be after write
        assert(!((out_bufq->first == out_bufq->last) &&
                 (out_bufq->write_idx < out_bufq->read_idx)));
    }
}
