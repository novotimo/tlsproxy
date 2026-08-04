#include "proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>

#include "errors.h"
#include "event.h"
#include "listen.h"
#include "logging.h"
#include "queue.h"
#include "timeutils.h"


#define TPX_SCRATCH_BUF_SIZE 4096

ngx_rbtree_t timeouts;
static ngx_rbtree_node_t sentinel;
uint32_t nproxies = 0;


int create_connect(proxy_t *proxy, int keepidle, int keepintvl, int keepcnt);


proxy_t *create_proxy(int accepted_fd, SSL *ssl,
                      listen_t *listener,
                      unsigned int conn_timeout,
                      int keepidle, int keepintvl, int keepcnt,
                      uint64_t shutdown_timeout, uint64_t shutdown_interval) {
    proxy_t *proxy = malloc(sizeof(proxy_t));
    if (!proxy) {
        log_system_err(LL_ERROR, "Couldn't allocate memory for proxy",
                       TPX_ERR_ERRNO);
        return NULL;
    }
    memset(proxy, '\0', sizeof(proxy_t));

    proxy->event_id = EV_PROXY;
    proxy->c2s = queue_new();
    proxy->s2c = queue_new();
    proxy->client_fd = accepted_fd;
    proxy->listener = listener;
    proxy->ssl = ssl;
    proxy->state = PS_CLIENT_CONNECTED;
    proxy->timer_set = 0;
    proxy->shutdown_timeout = shutdown_timeout;
    proxy->shutdown_interval = shutdown_interval;
    proxy->hand_shaken = 0;
    proxy->client_notified_close = 0;

    log_proxy(LL_DEBUG, proxy, "client_connect", NULL, NULL);

    if ((proxy->serv_fd = create_connect(proxy,
                                         keepidle, keepintvl, keepcnt)) == -1) {
        queue_free(proxy->c2s);
        queue_free(proxy->s2c);

        // fd hasn't been added to epoll yet, and SSL will be freed outside
        free(proxy);

        return NULL;
    }

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

        return NULL;
    }

    nproxies++;
    return proxy;
}

int create_connect(proxy_t *proxy, int keepidle, int keepintvl, int keepcnt) {
    assert(proxy);
    int conn_sock = socket(proxy->listener->peer_addr.ss_family, SOCK_STREAM,0);
    if (conn_sock < 0) {
        log_proxy(LL_ERROR, proxy, "ioerror", "Couldn't create connect socket",
                  strerror(errno));
        return -1;
    }
    
    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        log_proxy(LL_ERROR, proxy, "ioerror",
                  "Couldn't get socket flags of connect socket",
                  strerror(errno));
        close(conn_sock);
        return -1;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        log_proxy(LL_ERROR, proxy, "ioerror", "Couldn't set connect socket to "
                  "non-blocking mode", strerror(errno));
        close(conn_sock);
        return -1;
    }

    // It's *fine* if keepalive isn't set, we can still go. It just means that
    // the default Linux kernel keepalive of 72 hours is used
    int opt = 1;
    if (setsockopt(conn_sock, SOL_SOCKET, SO_KEEPALIVE,
                   &opt, sizeof(opt)) == -1)
        log_proxy(LL_WARN, proxy, "ioerror",
                  "Couldn't enable keepalive on connect socket",
                  strerror(errno));

    opt = keepidle;
    if (setsockopt(conn_sock, IPPROTO_TCP, TCP_KEEPIDLE,
                   &opt, sizeof(opt)) == -1)
        log_proxy(LL_WARN, proxy, "ioerror",
                  "Couldn't set keepidle on connect socket", strerror(errno));

    opt = keepintvl;
    if (setsockopt(conn_sock, IPPROTO_TCP, TCP_KEEPINTVL,
                   &opt, sizeof(opt)) == -1)
        log_proxy(LL_WARN, proxy, "ioerror",
                  "Couldn't set keepintvl on connect socket", strerror(errno));

    opt = keepcnt;
    if (setsockopt(conn_sock, IPPROTO_TCP, TCP_KEEPCNT,
                   &opt, sizeof(opt)) == -1)
        log_proxy(LL_WARN, proxy, "ioerror",
                  "Couldn't set keepcnt on connect socket", strerror(errno));

    return conn_sock;
}

tpx_err_t proxy_handle_connect(proxy_t *proxy, unsigned int conn_timeout) {
    assert(proxy->state == PS_CLIENT_CONNECTED ||
           proxy->state == PS_SERVER_CONNECTING);
    int retcode = connect(proxy->serv_fd,
                          (struct sockaddr *)&proxy->listener->peer_addr,
                          proxy->listener->peer_addrlen);
    if (retcode == -1 && errno != EINPROGRESS && errno != EALREADY) {
        log_proxy(LL_ERROR, proxy, "ioerror", "Couldn't connect socket",
                  strerror(errno));
        return TPX_FAILURE;
    } else if (retcode == -1 && (errno == EINPROGRESS || errno == EALREADY)) {
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
        log_proxy(LL_DEBUG, proxy, "server_connect", NULL, NULL);
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
        log_proxy(LL_ERROR, proxy, "ioerror",
                  "Couldn't add server socket to epoll", strerror(errno));
        return TPX_FAILURE;
    }
    
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = client_proxy;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serv_proxy->client_fd, &ev) == -1) {
        log_proxy(LL_ERROR, proxy, "ioerror",
                  "Couldn't add client socket to epoll", strerror(errno));
        epoll_ctl(epollfd, EPOLL_CTL_DEL, serv_proxy->serv_fd, NULL);
        return TPX_FAILURE;
    }
    return TPX_SUCCESS;
}

void proxy_close(proxy_t *proxy, int epollfd) {
    if (proxy->timer_set) {
        ngx_rbtree_delete(&timeouts, &proxy->timer);
        proxy->timer_set = 0;
    }

    if (!proxy->hand_shaken) {
        proxy->hand_shaken = 1;
        log_handshake(LL_DEBUG, proxy, "failed");
    }

    switch (proxy->state) {
    case PS_CLIENT_CONNECTED:
    case PS_SERVER_CONNECTING:
    case PS_SERVER_DISCONNECTED:
    case PS_CLIENT_FLUSHED:
    case PS_CLOSE_NOTIFY_SENT:
        log_proxy(LL_DEBUG, proxy, "client_disconnect", "Other side disconnect",
                  NULL);
        break;
    case PS_CLIENT_DISCONNECTED:
        log_proxy(LL_DEBUG, proxy, "server_disconnect", "Other side disconnect",
                  NULL);
        break;
    default:
        break;
    }
    
    if (proxy->ssl)
        SSL_free(proxy->ssl);
    proxy->ssl = NULL;

    if (epollfd != -1 && proxy->serv_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, proxy->serv_fd, NULL) == -1)
            log_system_err(LL_WARN, "Failure deleting server socket from epoll",
                           TPX_ERR_ERRNO);
    }
    if (epollfd != -1 && proxy->client_fd != -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, proxy->client_fd, NULL) == -1)
            log_system_err(LL_WARN, "Failure deleting client socket from epoll",
                           TPX_ERR_ERRNO);
    }

    queue_free(proxy->c2s);
    queue_free(proxy->s2c);
    
    if (proxy->serv_fd != -1)
        close(proxy->serv_fd);
    if (proxy->client_fd != -1)
        close(proxy->client_fd);
    free(proxy);
    nproxies--;
}

tpx_err_t handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                       uint8_t tag) {
    tpx_err_t ret = TPX_SUCCESS;
    int is_client = tag & 1;
    switch (proxy->state) {
    case PS_CLIENT_CONNECTED:
    case PS_SERVER_CONNECTING:
        if (!is_client) {
            ret = proxy_handle_connect(proxy, 0);
            if (ret == TPX_AGAIN)
                proxy->state = PS_SERVER_CONNECTING;
            else if (ret == TPX_SUCCESS)
                proxy->state = PS_READY;
            else if (ret == TPX_FAILURE) {
                proxy_close(proxy, epollfd);
                ret = TPX_CLOSED;
            }
            return ret;
        }
        // If we're the server socket we keep going
        __attribute__((fallthrough));
    case PS_READY:
        assert(events);
        if (0 != (events & EPOLLOUT))
            ret = proxy_handle_write(proxy, is_client);

        if (ret != TPX_SUCCESS) {
            if (is_client)
                proxy->state = PS_CLIENT_DISCONNECTED;
            else
                proxy->state = PS_SERVER_DISCONNECTED;
            break;
        }
    
        if (0 != (events & EPOLLIN))
            ret = proxy_handle_read(proxy, is_client);
        
        if (ret != TPX_SUCCESS) {
            if (is_client)
                proxy->state = PS_CLIENT_DISCONNECTED;
            else {
                // If we haven't finished our handshake, just quit
                if (!proxy->hand_shaken) {
                    shutdown(proxy->client_fd, SHUT_WR);
                    proxy_close(proxy, epollfd);
                    return TPX_CLOSED;
                }
                
                // proxy_handle_read has just finished, and we've either
                // received an error or an EOF.
                close(proxy->serv_fd);
                proxy->serv_fd = -1;

                // We want to shutdown within `shutdown_time` seconds,
                // whatever happens
                assert(!proxy->timer_set);
                proxy->timer.key = proxy->shutdown_time =
                    gettime() + proxy->shutdown_timeout * 1000;
                ngx_rbtree_insert(&timeouts, &proxy->timer);
                proxy->timer_set = 1;
                
                proxy->state = PS_SERVER_DISCONNECTED;
            }

            break;
        }
        return TPX_SUCCESS;
    case PS_SERVER_DISCONNECTED:
    case PS_CLIENT_FLUSHED:
    case PS_CLOSE_NOTIFY_SENT:
    case PS_CLIENT_DISCONNECTED:
        break;
    default:
        log_system_err(LL_ERROR, "Event queue corrupted: unexpected state",
                       TPX_ERR_PLAIN);
        return TPX_FAILURE;

    }

    if (proxy->state == PS_CLIENT_DISCONNECTED) {
        proxy_close(proxy, epollfd);
        return TPX_CLOSED;
    }

    // Ignore all server events if we're in the last 3 graceful shutdown states
    if (!is_client)
        return TPX_SUCCESS;

    // Save this for later when we want to shut down the SSL context
    int shutdown_rc = 0;
    int shutdown_err = 0;

    // Now we handle the graceful shutdown, separately from the rest
    // because we need to make sure we do all we can until we get a real
    // block (WANT_WRITE or EAGAIN)
    switch (proxy->state) {
    case PS_SERVER_DISCONNECTED:
        if ((!proxy->client_notified_close &&
             error_rc_bad(proxy_ignore_read(proxy, 1))) ||
            error_rc_bad(proxy_handle_write(proxy, 1))) {
            // If we get a failure, we can just directly close the client.
            // If SSL_read returns -1 with SSL_ERROR_ZERO_RETURN, we don't
            // need to do this anymore
            shutdown(proxy->client_fd, SHUT_WR);
            proxy_close(proxy, epollfd);
            return TPX_CLOSED;
        }

        // If we've finished our reads and writes with successes but
        // still have data to flush, we're waiting in WANT_READ or WANT_WRITE.
        // So, just go back to epoll
        if (!outbuf_empty(proxy, 1))
            return TPX_SUCCESS;
        // But if we're done, we need to immediately go to our next state and
        // do the work, because we're edge triggered on epoll and could receive
        // nothing more
        proxy->state = PS_CLIENT_FLUSHED;

        __attribute__((fallthrough));
    case PS_CLIENT_FLUSHED:
        // Now that our client's flushed, we should give an SSL_shutdown to
        // send our close_notify message.
        shutdown_rc = SSL_shutdown(proxy->ssl);
        shutdown_err = SSL_get_error(proxy->ssl, shutdown_rc);
        if (shutdown_rc == -1 && shutdown_err == SSL_ERROR_WANT_WRITE)
            return TPX_SUCCESS;
        else if (shutdown_rc == -1 && shutdown_err != SSL_ERROR_WANT_READ) {
            // We got a deadly client socket error, we can just close now
            shutdown(proxy->client_fd, SHUT_WR);
            proxy_close(proxy, epollfd);
            return TPX_CLOSED;
        } else if (shutdown_rc == 1) {
            shutdown(proxy->client_fd, SHUT_WR);
            proxy_close(proxy, epollfd);
            return TPX_CLOSED;
        }

        // If we're in WANT_READ, all we need to do is send our FIN
        // and close down the write part of the socket. Then, we can
        // just keep reading until the client shuts up.
        shutdown(proxy->client_fd, SHUT_WR);

        proxy->state = PS_CLOSE_NOTIFY_SENT;

        __attribute__((fallthrough));
    case PS_CLOSE_NOTIFY_SENT:

        // If we get a read error or a close_notify, we're done
        if (error_rc_bad(proxy_ignore_read(proxy, 1)) ||
            proxy->client_notified_close) {
            proxy_close(proxy, epollfd);
            return TPX_CLOSED;
        }

        // Now our close_notify is sent, we're onto lingering.
        // We want a new timeout every single time we're here
        ngx_rbtree_delete(&timeouts, &proxy->timer);
        proxy->timer.key = MIN(gettime() + proxy->shutdown_interval * 1000,
                               proxy->shutdown_time);
        ngx_rbtree_insert(&timeouts, &proxy->timer);

        return TPX_SUCCESS;
    }

    // Unreachable
    assert(0);
    return TPX_FAILURE;
}

tpx_err_t proxy_handle_read(proxy_t *proxy, int is_client) {
    unsigned char *rdbuf = NULL;
    size_t buflen = 0;

    bufq_t *in_bufq;
    int fd;
    if (is_client) {
        in_bufq = proxy->c2s;
        // Not actually used, but makes things clearer
        fd = proxy->client_fd;
    } else {
        in_bufq = proxy->s2c;
        fd = proxy->serv_fd;
    }

    // Invariants
    assert(in_bufq->write_idx < TPX_NET_BUFSIZE);
    assert(queue_empty(in_bufq) == (in_bufq->write_idx == -1));
    assert(buflen < INT_MAX);

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
            log_system_err(LL_ERROR, "Buffer queue corrupted", TPX_ERR_PLAIN);
            return TPX_FAILURE;
        case TPX_EMPTY:
            log_system_err(LL_ERROR, "Buffer queue corrupted: index isn't -1 "
                           "but the queue is empty", TPX_ERR_PLAIN);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(in_bufq->write_idx < (int)buflen);
        }
    }

    int nbytes = -1;
    if (proxy->ssl) ERR_clear_error();
    while ((int)buflen > in_bufq->write_idx &&
           ((nbytes = DO_READ(proxy->ssl, fd,
                              rdbuf + in_bufq->write_idx,
                              (size_t)((int)buflen - in_bufq->write_idx))) > 0)) {
        assert((int)buflen >= nbytes);
        if (in_bufq->write_idx + nbytes == (int)buflen) {
            rdbuf = malloc(TPX_NET_BUFSIZE);
            buflen = TPX_NET_BUFSIZE;
            enqueue(in_bufq, rdbuf, buflen);
            in_bufq->write_idx = 0;
        } else {
            in_bufq->write_idx += nbytes;
        }
    }
    
    if (!proxy->hand_shaken && SSL_is_init_finished(proxy->ssl)) {
        proxy->hand_shaken = 1;
        log_handshake(LL_DEBUG, proxy, "granted");
    }

    // Invariants
    assert(in_bufq->write_idx < TPX_NET_BUFSIZE);
    assert(queue_empty(in_bufq) == (in_bufq->write_idx == -1));

    if (is_client && nbytes <= 0) {
        if (proxy_handle_ssl_failure(proxy, nbytes) == TPX_CLOSED) {
            return TPX_CLOSED;
        }
    } else if (!is_client && nbytes == -1) {
        switch (errno) {
        case EAGAIN:
            break;
        case ECONNRESET:
        case EPIPE:
            log_system_err(LL_DEBUG, "Couldn't read bytes from server socket",
                           TPX_ERR_ERRNO);
            return TPX_CLOSED;
        default:
            log_system_err(LL_ERROR, "Couldn't read bytes from server socket",
                       TPX_ERR_ERRNO);
            return TPX_CLOSED;
        }
    } else if (!is_client && nbytes == 0) {
        log_proxy(LL_DEBUG, proxy, "server_disconnect", "EOF received", NULL);
        proxy_process_data(proxy, is_client);
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

    bufq_t *out_bufq;
    int fd;
    if (is_client) {
        out_bufq = proxy->s2c;
        // Not actually used, but makes things clearer
        fd = proxy->client_fd;
    } else {
        out_bufq = proxy->c2s;
        fd = proxy->serv_fd;
    }

    /* This is true as proxy_handle_write is only called after proxy_handle_read */
    assert(out_bufq->write_idx > 0);
    
    int nsent = 0;
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
            log_system_err(LL_ERROR, "The buffer queue is corrupted",
                           TPX_ERR_PLAIN);
            return TPX_FAILURE;
        case TPX_SUCCESS:
        default:
            assert(wbuf);
            // Get only the part of the buf that's got data in it
            if (out_bufq->first == out_bufq->last)
                real_buflen = (size_t)out_bufq->write_idx;
            else
                real_buflen = wbuflen;
            
            if (proxy->ssl) ERR_clear_error();
            while ((int)real_buflen > out_bufq->read_idx &&
                   (nsent = DO_SEND(proxy->ssl, fd,
                                    wbuf + out_bufq->read_idx,
                                    (size_t)((int)real_buflen - out_bufq->read_idx)))
                   > 0) {
                out_bufq->read_idx += nsent;
            }
            
            if (!proxy->hand_shaken && SSL_is_init_finished(proxy->ssl)) {
                proxy->hand_shaken = 1;
                log_handshake(LL_DEBUG, proxy, "granted");
            }

            // Are we done with this chunk?
            if (out_bufq->read_idx == (int)wbuflen) {
                dequeue(out_bufq, NULL, NULL);
                free(wbuf);
                out_bufq->read_idx = 0;
            } else if (out_bufq->read_idx == (int)real_buflen) {
                // This means wbuflen != real_buflen so we're at the
                // end of the chunk currently being written
                return TPX_SUCCESS;
            }

            if (is_client && nsent <= 0) {
                return proxy_handle_ssl_failure(proxy, nsent);
            } else if (!is_client && nsent == -1) {
                switch (errno) {
                case EAGAIN:
                    return TPX_SUCCESS;
                case ECONNRESET:
                case EPIPE:
                    log_proxy(LL_DEBUG, proxy, "server_disconnect",
                              "Couldn't send bytes to server socket",
                              strerror(errno));
                    break;
                default:
                    log_proxy(LL_ERROR, proxy, "server_disconnect",
                              "Couldn't send bytes to server socket",
                              strerror(errno));
                    break;
                }
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

void proxy_init_timeouts(void) {
    ngx_rbtree_init(&timeouts, &sentinel, &ngx_rbtree_insert_timer_value);
}

void proxy_handle_timeout(proxy_t *proxy, int epollfd) {
    // If this is a connection timeout
    if (proxy->state < PS_SERVER_DISCONNECTED)
        shutdown(proxy->client_fd, SHUT_WR);
    proxy_close(proxy, epollfd);
}

tpx_err_t proxy_handle_ssl_failure(proxy_t *proxy, int retcode) {
    switch(SSL_get_error(proxy->ssl, retcode)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return TPX_SUCCESS;
    case SSL_ERROR_SYSCALL:
        switch (errno) {
        case EAGAIN:
            // This doesn't actually happen
            return TPX_SUCCESS;
        case ECONNRESET:
        case EPIPE:
            log_proxy(LL_DEBUG, proxy, "client_disconnect",
                      "Couldn't communicate with client socket",
                      strerror(errno));
            break;
        default:
            log_proxy(LL_ERROR, proxy, "client_disconnect",
                      "Couldn't communicate with client socket",
                      strerror(errno));
            break;
        }
        
        if (!proxy->hand_shaken) {
            proxy->hand_shaken = 1;
            log_handshake(LL_DEBUG, proxy, "failed");
        }
        
        return TPX_CLOSED;
    case SSL_ERROR_ZERO_RETURN:
        if (!proxy->hand_shaken) {
            proxy->hand_shaken = 1;
            log_handshake(LL_DEBUG, proxy, "denied");
        }

        log_proxy(LL_DEBUG, proxy, "client_disconnect",
                  "EOF received", NULL);
        return TPX_CLOSED;
    default:
        if (!proxy->hand_shaken) {
            proxy->hand_shaken = 1;
            log_handshake(LL_DEBUG, proxy, "denied");
        }
        
        log_proxy(LL_ERROR, proxy, "client_disconnect",
                  "Couldn't communicate with client socket", NULL);
        return TPX_CLOSED;
    }
}

tpx_err_t proxy_ignore_read(proxy_t *proxy, int is_client) {
    // TODO: add define for this
    unsigned char rdbuf[TPX_SCRATCH_BUF_SIZE];

    // Don't use this in server mode for now.
    assert(is_client == 1);

    int nbytes = -1;
    int fd = proxy->client_fd;
    if (proxy->ssl) ERR_clear_error();
    while ((nbytes = DO_READ(proxy->ssl, fd, rdbuf, sizeof(rdbuf))) > 0);
    
    if (!proxy->hand_shaken && SSL_is_init_finished(proxy->ssl)) {
        proxy->hand_shaken = 1;
        log_handshake(LL_DEBUG, proxy, "granted");
    }

    if (is_client && nbytes <= 0) {
        if (SSL_get_error(proxy->ssl, nbytes) == SSL_ERROR_ZERO_RETURN) {
            proxy->client_notified_close = 1;
            return TPX_SUCCESS;
        } else if (proxy_handle_ssl_failure(proxy, nbytes) == TPX_CLOSED)
            return TPX_CLOSED;
    }
    return TPX_SUCCESS;
}
