#include "proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "errors.h"

tpx_err_t tpx_proxy_dispatch(connection_t *conn, int epollfd, uint32_t events,
                               SSL_CTX *ssl_ctx) {
    int ret = TPX_SUCCESS;
    switch (conn->state) {
    case CS_LISTENING:
        assert(conn->handle_accept);
        if (0 != (events | EPOLLIN) && conn->handle_accept) {
            queue_t *bufq_c2s = tpx_queue_new();
            queue_t *bufq_s2c = tpx_queue_new();
            connection_t *newconn =
                (conn->handle_accept)(conn, ssl_ctx, bufq_c2s, bufq_s2c);
            if (!newconn) {
                tpx_queue_free(bufq_c2s);
                tpx_queue_free(bufq_s2c);
                return TPX_FAILURE;
            }

            // Add both fds to epoll
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
            ev.data.ptr = newconn;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, newconn->fd, &ev) == -1)
                err(EXIT_FAILURE, "tpx_handle_all: epoll_ctl1");

            newconn = newconn->proxy->plain;
            ev.data.ptr = newconn;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, newconn->fd, &ev) == -1)
                err(EXIT_FAILURE, "tpx_handle_all: epoll_ctl2");
        }
        break;
    case CS_CONNECTING:
        if (0 != (events | EPOLLOUT) && conn->handle_connect)
            return (conn->handle_connect)(conn);
    case CS_CONNECTED:
        // We want to handle writes first so that the queue doesn't
        // grow as big
        if (0 != (events | EPOLLOUT) && conn->handle_write)
            ret = (conn->handle_write)(conn);
        if (ret != TPX_SUCCESS)
            return ret;
    
        if (0 != (events | EPOLLIN) && conn->handle_read)
            return (conn->handle_read)(conn);
        break;
    case CS_CLOSING:
        ret = tpx_conn_shutdown(conn);
        if (ret == TPX_SUCCESS || ret == TPX_FAILURE) {
            conn->proxy->state = PS_DONE;
            tpx_proxy_close(conn, epollfd);
        }
        break;
    case CS_DONE:
    case CS_CLOSED:
        // This should never happen I think
        assert(0);
    }
    return ret;
}


connection_t *tpx_proxy_listen(const char *lhost, const unsigned short lport,
                               const char *thost, const unsigned short tport) {
    connection_t *listener = tpx_create_listener(lhost, lport);

    listener->handle_accept = &tpx_proxy_accept;

    // Add remote connect address to listener
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    char service[6];
    snprintf(service, sizeof(service), "%d", tport);
    
    struct addrinfo *connect_addr;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    int error = getaddrinfo(thost, service, &hints, &connect_addr);
    if (error != 0)
        errx(EXIT_FAILURE, "getaddrinfo for listener: %s",
             gai_strerror(error));

    memcpy(&listener->peer_addr, connect_addr->ai_addr, connect_addr->ai_addrlen);
    listener->peer_addrlen = connect_addr->ai_addrlen;
    freeaddrinfo(connect_addr);
    return listener;
}

connection_t *tpx_proxy_accept(connection_t *conn, SSL_CTX *ssl_ctx,
                          queue_t *bufq_c2s, queue_t *bufq_s2c) {
    connection_t *enc_conn =
        tpx_handle_accept(conn, ssl_ctx, bufq_c2s, bufq_s2c);
    if (!enc_conn)
        return NULL;
    
    enc_conn->handle_process = &tpx_proxy_client_process;

    connection_t *plain_conn =
        tpx_create_connect((struct sockaddr *)&conn->peer_addr, conn->peer_addrlen,
                           bufq_s2c, bufq_c2s);
    if (!plain_conn) {
        (enc_conn->handle_close)(enc_conn);
        return NULL;
    }

    plain_conn->handle_process = &tpx_proxy_server_process;
    plain_conn->handle_connect = &tpx_proxy_handle_connect;

    proxy_t *proxy = calloc(1, sizeof(proxy_t));
    proxy->enc = enc_conn;
    proxy->plain = plain_conn;
    proxy->state = PS_CLIENT_CONNECTED;

    enc_conn->proxy = proxy;
    plain_conn->proxy = proxy;

    return enc_conn;
}

tpx_err_t tpx_proxy_handle_connect(connection_t *conn) {
    proxy_t *proxy = conn->proxy;

    if (connect(conn->fd, (struct sockaddr *)&conn->peer_addr,
                conn->peer_addrlen) == 0) {
        proxy->state = PS_READY;
        conn->state = CS_CONNECTED;
        return TPX_SUCCESS;
    } else if (errno == EAGAIN) {
        conn->state = CS_CONNECTING;
        return TPX_SUCCESS;
    } else {
        perror("tpx_proxy_handle_connect");
        return TPX_FAILURE;
    }

}


tpx_err_t tpx_proxy_client_process(connection_t *conn) {
    return (conn->proxy->plain->handle_write)(conn->proxy->plain);
}

tpx_err_t tpx_proxy_server_process(connection_t *conn) {
    return (conn->proxy->enc->handle_write)(conn->proxy->enc);
}

void tpx_proxy_close(connection_t *conn, int epollfd) {
    proxy_t *proxy = conn->proxy;
    connection_t *enc = proxy->enc;
    connection_t *plain = proxy->plain;

    assert(conn==enc || conn==plain);
    if (conn == plain && proxy->state == PS_READY) {
        proxy->state = PS_SERVER_DISCONN;
        enc->state = CS_CLOSING;
        if (tpx_conn_shutdown(conn) == 1) {
            free(proxy);
            // Both conns use the same buffers so they only need freeing once
            tpx_queue_free(enc->in_bufq);
            tpx_queue_free(enc->out_bufq);
        
            tpx_conn_close(enc, epollfd);
            tpx_conn_close(plain, epollfd);
        }
    } else if (proxy->state == PS_SERVER_DISCONN ||
               proxy->state == PS_READY ||
               proxy->state == PS_CLIENT_CONNECTED) {
        free(proxy);
        // Both conns use the same buffers so they only need freeing once
        tpx_queue_free(enc->in_bufq);
        tpx_queue_free(enc->out_bufq);
        
        tpx_conn_close(enc, epollfd);
        tpx_conn_close(plain, epollfd);
    } else {
        errx(EXIT_FAILURE, "Called tpx_proxy_close in state %d", conn->state);
    }
}
