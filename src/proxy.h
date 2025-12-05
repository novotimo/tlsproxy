#ifndef __TLSPROXY_PROXY_H
#define __TLSPROXY_PROXY_H

#include <openssl/ssl.h>
#include <stdint.h>
#include <sys/socket.h>

#include "errors.h"
#include "queue.h"


#define TPX_NET_BUFSIZE 16384

#define DO_READ(ssl, fd, buf, bufsize) \
    is_client ? SSL_read(ssl,buf,bufsize) : read(fd,buf,bufsize)

#define DO_SEND(ssl, fd, buf, bufsize) \
    is_client ? SSL_write(ssl,buf,bufsize) : send(fd,buf,bufsize,0)


typedef enum proxy_state_e {
    PS_CLIENT_CONNECTED,
    PS_SERVER_CONNECTING,
    PS_READY,
    PS_SERVER_DISCONNECTED,
    PS_CLIENT_DISCONNECTED
} proxy_state_t;

/**
 * @brief The data structure shared between both fds of a proxy tunnel.
 *
 * This proxy_s is the event context that holds all info for the proxy.
 * In the effort to deduplicate data, this same structure is assigned
 * to both sockets in the proxy pair. But how can we distinguish
 * which socket an event that we receive from epoll refers to? Well, using
 * tagged pointers of course: if ptr & 1 == 1, it's an event on the client
 * fd, and if ptr & 1 == 0, it's on the server fd.
 */
typedef struct proxy_s {
    // This will be one of the enum values from event.h
    uint8_t event_id;

    bufq_t *c2s;
    bufq_t *s2c;

    // All sockets must be set to -1 once they're closed
    int client_fd;
    int serv_fd;

    struct sockaddr_storage server_addr;
    socklen_t server_addrlen;

    SSL *ssl;
    proxy_state_t state;
} proxy_t;

typedef struct listen_s listen_t;


void handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                  void *ssl_ctx, uint8_t tag);
proxy_t *create_proxy(int accepted_fd, listen_t *listen, SSL *ssl,
                      struct sockaddr const* server_addr,
                      socklen_t server_addrlen);

tpx_err_t proxy_add_to_epoll(proxy_t *proxy, int epollfd);

tpx_err_t proxy_handle_connect(proxy_t *proxy);
tpx_err_t proxy_handle_read(proxy_t *proxy, int is_client);
tpx_err_t proxy_handle_write(proxy_t *proxy, int is_client);
tpx_err_t proxy_process_data(proxy_t *proxy, int is_client);

// When you want to close a proxy, keep calling this on each
// epoll event and the events will eventually stop
void proxy_close(proxy_t *proxy, int epollfd);


#endif
