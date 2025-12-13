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
#include "logging.h"
#include "queue.h"
#include "timeutils.h"


ngx_rbtree_t timeouts;
static ngx_rbtree_node_t sentinel;


int create_connect(proxy_t *proxy);


proxy_t *create_proxy(int accepted_fd, SSL *ssl,
                      struct sockaddr const* server_addr,
                      socklen_t server_addrlen,
                      unsigned int conn_timeout) {
    proxy_t *proxy = malloc(sizeof(proxy_t));
    if (!proxy) {
        log_errno(LL_ERROR, "Couldn't allocate memory for proxy");
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
    tpx_err_t ret = proxy_handle_connect(proxy, conn_timeout);
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
        
        proxy = NULL;
    }

    return proxy;
}

int create_connect(proxy_t *proxy) {
    assert(proxy);
    int conn_sock = socket(proxy->server_addr.ss_family, SOCK_STREAM, 0);
    if (conn_sock < 0) {
        log_errno(LL_ERROR, "Couldn't create connect socket");
        return -1;
    }
    
    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        log_errno(LL_ERROR, "Couldn't get socket flags of connect socket");
        return -1;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        log_errno(LL_ERROR, "Couldn't set connect socket to non-blocking mode");
        return -1;
    }
    return conn_sock;
}

tpx_err_t proxy_handle_connect(proxy_t *proxy, unsigned int conn_timeout) {
    assert(proxy->state == PS_CLIENT_CONNECTED ||
           proxy->state == PS_SERVER_CONNECTING);
    int retcode = connect(proxy->serv_fd,
                          (struct sockaddr *)&proxy->server_addr,
                          proxy->server_addrlen);
    if (retcode == -1 && errno != EINPROGRESS) {
        log_errno(LL_ERROR, "Couldn't connect socket");
        return TPX_FAILURE;
    } else if (retcode == -1 && errno == EINPROGRESS) {
        if (proxy->state == PS_CLIENT_CONNECTED) {
            // This is the first time we've tried this, need to set a timeout
            // Hardcoded to 3 seconds for now
            proxy->timer.key = gettime() + conn_timeout;
            ngx_rbtree_insert(&timeouts, &proxy->timer);
            proxy->timer_set = 1;
        }
        return TPX_AGAIN;
    } else if (retcode == 0 && proxy->state == PS_CLIENT_CONNECTED) {
        return TPX_SUCCESS;
    } else {
        ngx_rbtree_delete(&timeouts, &proxy->timer);
        proxy->timer_set = 0;
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
        log_errno(LL_ERROR, "Couldn't add server socket to epoll");
        return TPX_FAILURE;
    }
    
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = client_proxy;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serv_proxy->client_fd, &ev) == -1) {
        log_errno(LL_ERROR, "Couldn't add client socket to epoll");
        epoll_ctl(epollfd, EPOLL_CTL_DEL, serv_proxy->serv_fd, NULL);
        return TPX_FAILURE;
    }
    return TPX_SUCCESS;
}

tpx_err_t proxy_close(proxy_t *proxy, int epollfd) {
    if (proxy->timer_set) {
        ngx_rbtree_delete(&timeouts, &proxy->timer);
        proxy->timer_set = 0;
    }
    if (proxy->state == PS_CLIENT_DISCONNECTED) {
        if (proxy->ssl)
            SSL_free(proxy->ssl);
        proxy->ssl = NULL;
    } else if (proxy->state == PS_SERVER_DISCONNECTED) {
        if (proxy->ssl) {
            // If the shutdown isn't done yet
            if (SSL_shutdown(proxy->ssl) == 0)
                return TPX_AGAIN;
            SSL_free(proxy->ssl);
            proxy->ssl = NULL;
        }
    } else if (proxy->state == PS_SERVER_CONNECTING) {
        if (proxy->ssl)
            SSL_free(proxy->ssl);
        proxy->ssl = NULL;
    }
    
    if (epollfd != -1 && proxy->serv_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, proxy->serv_fd, NULL) == -1)
            log_errno(LL_WARN, "Failure deleting server socket from epoll");
    }
    if (epollfd != -1 && proxy->client_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, proxy->client_fd, NULL) == -1)
            log_errno(LL_WARN, "Failure deleting client socket from epoll");
    }

    queue_free(proxy->c2s);
    queue_free(proxy->s2c);
    
    if (proxy->serv_fd != -1)
        close(proxy->serv_fd);
    if (proxy->client_fd != -1)
        close(proxy->client_fd);
    free(proxy);
    return TPX_CLOSED;
}

tpx_err_t handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                       void *ssl_ctx, uint8_t tag, unsigned int conn_timeout) {
    tpx_err_t ret = TPX_SUCCESS;
    switch (proxy->state) {
    case PS_CLIENT_CONNECTED:
    case PS_SERVER_CONNECTING:
        if (0 == (tag & 1)) {
            ret = proxy_handle_connect(proxy, conn_timeout);
            if (ret == TPX_AGAIN)
                proxy->state = PS_SERVER_CONNECTING;
            else if (ret == TPX_SUCCESS)
                proxy->state = PS_READY;
            else if (ret == TPX_FAILURE)
                ret = proxy_close(proxy, epollfd);
            return ret;
        }
        // If we're the server socket we keep going
    case PS_READY:
        assert(events);
        if (0 != (events & EPOLLOUT))
            ret = proxy_handle_write(proxy, tag);

        if (ret != TPX_SUCCESS) {
            if (0 != (tag & 1))
                proxy->state = PS_CLIENT_DISCONNECTED;
            else
                proxy->state = PS_SERVER_DISCONNECTED;
            break;
        }
    
        if (0 != (events & EPOLLIN))
            ret = proxy_handle_read(proxy, tag);
        
        if (ret != TPX_SUCCESS) {
            if (0 != (tag & 1))
                proxy->state = PS_CLIENT_DISCONNECTED;
            else
                proxy->state = PS_SERVER_DISCONNECTED;
            break;
        }
        return TPX_SUCCESS;
    default:
        break;
    }
    if (proxy->state == PS_SERVER_DISCONNECTED ||
        proxy->state == PS_CLIENT_DISCONNECTED) {
        if (proxy_close(proxy, epollfd) == TPX_CLOSED)
            return TPX_CLOSED;
        else
            return TPX_SUCCESS;
    }

    log_msg(LL_ERROR, "This event is corrupted: unexpected state %d",
            proxy->state);
    return TPX_FAILURE;
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
            log_msg(LL_ERROR, "The queue @ 0x%p is corrupted! To stay safe,"
                    " the memory will be leaked", in_bufq);
            return TPX_FAILURE;
        case TPX_EMPTY:
            log_msg(LL_ERROR, "The queue @ 0x%p is corrupted: in_bufq->"
                    "write_idx isn't -1 but the queue is empty", in_bufq);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(in_bufq->write_idx < buflen);
        }
    }

    int nbytes = -1;
    if (proxy->ssl) ERR_clear_error();
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

    if (is_client && nbytes <= 0) {
        if (proxy_handle_ssl_failure(proxy->ssl, nbytes) == TPX_CLOSED) {
            return TPX_CLOSED;
        }
    } else if (!is_client && nbytes == -1 && errno != EAGAIN) {
        log_errno(LL_INFO, "Couldn't read bytes from server socket");
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
            log_msg(LL_ERROR, "The queue @ 0x%p is corrupted! To stay safe,"
                    " the memory will be leaked", out_bufq);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(wbuf);
            // Get only the part of the buf that's got data in it
            if (out_bufq->first == out_bufq->last)
                real_buflen = out_bufq->write_idx;
            else
                real_buflen = wbuflen;
            
            if (proxy->ssl) ERR_clear_error();
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

            if (is_client && nsent <= 0) {
                return proxy_handle_ssl_failure(proxy->ssl, nsent);
            } else if (!is_client && nsent == -1) {
                if (errno != EAGAIN) {
                    log_errno(LL_INFO, "Couldn't send bytes to server socket");
                    return TPX_CLOSED;
                }
                return TPX_SUCCESS;
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

void proxy_init_timeouts() {
    ngx_rbtree_init(&timeouts, &sentinel, &ngx_rbtree_insert_timer_value);
}

tpx_err_t proxy_handle_timeout(proxy_t *proxy, int epollfd) {
    return proxy_close(proxy, epollfd);
}

tpx_err_t proxy_handle_ssl_failure(SSL *ssl, int retcode) {
    int sslerr = SSL_get_error(ssl, retcode);
    switch(SSL_get_error(ssl, retcode)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return TPX_SUCCESS;
    case SSL_ERROR_SYSCALL:
        log_errno(LL_ERROR, "Couldn't communicate with client socket");
        return TPX_CLOSED;
    case SSL_ERROR_ZERO_RETURN:
        return TPX_CLOSED;
    default:
        log_ossl(LL_ERROR, "Couldn't communicate with client socket");
        return TPX_CLOSED;
    }
}
