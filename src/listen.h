#ifndef __TLSPROXY_LISTEN_H
#define __TLSPROXY_LISTEN_H

#include <stdint.h>
#include <sys/socket.h>

#include "errors.h"


typedef struct listen_s {
    uint8_t event_id;
    int fd;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
} listen_t;


/**
 * @brief Accepts a connection on the listen socket.
 *
 * This accepts the connection on the listen socket, makes a proxy
 * from that connection, and pushes it to the epollfd.
 * @param listen The listen context
 * @param epollfd The epoll fd
 * @param events The epoll events ready on the socket
 * @param ssl_ctx The OpenSSL ctx which should contain a fully built cert
 *                chain and also be otherwise initialized.
 */
tpx_err_t handle_accept(listen_t *listen, int epollfd, uint32_t events,
                        void *ssl_ctx);

/**
 * @brief Makes a connection ctx for a listen socket.
 *
 * Creates a listener socket using the host and port provided,
 * and saves it in a connection_t. Creates the socket,
 * sets it to nonblocking mode, sets SO_REUSEADDR | SO_REUSEPORT,
 * binds the socket and starts listening.
 * @param host The hostname or IP address of the interface to listen
 *             on. If this is 0.0.0.0, listen on all addresses,
 *             including IPv6 ones.
 * @param port The port to listen on.
 * @return The connection context created.
 */
listen_t *create_listener(const char *lhost, const unsigned short lport,
                          const char *thost, const unsigned short tport);

#endif
