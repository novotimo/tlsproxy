#ifndef __TLSPROXY_LISTEN_H
#define __TLSPROXY_LISTEN_H

#include <stdint.h>
#include <sys/socket.h>

#include "errors.h"


/** @brief Holds the context for a listen socket */
typedef struct listen_s {
    uint8_t event_id; /**< @brief EV_LISTEN */
    int fd; /**< @brief The listening socket */

    struct sockaddr_storage peer_addr; /**< @brief The target address to connect
                                        * to once we get a connection on this */
    socklen_t peer_addrlen; /**< @brief The address length of peer_addr */
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
 * @return The outcome of handling the event, either TPX_SUCCESS or TPX_FAILURE.
 */
tpx_err_t handle_accept(listen_t *listen, int epollfd, uint32_t events,
                        void *ssl_ctx, unsigned int conn_timeout);

/**
 * @brief Makes a connection ctx for a listen socket.
 *
 * Creates a listener socket using the host and port provided,
 * and saves it in a connection_t. Creates the socket,
 * sets it to nonblocking mode, sets SO_REUSEADDR | SO_REUSEPORT,
 * binds the socket and starts listening.
 * @param lhost The hostname or IP address of the interface to listen
 *              on. Set this to 0.0.0.0 or ::0 to listen on all addresses.
 * @param lport The port to listen on.
 * @param thost The hostname or IP address of the backend server to connect to.
 * @param tport The port of the backend server.
 * @return The connection context created or NULL if it failed.
 */
listen_t *create_listener(const char *lhost, const unsigned short lport,
                          const char *thost, const unsigned short tport);

/**
 * @brief Creates a socket and binds to it
 * @param host The hostname or IP address of the local interface to
 *        bind to. This can be 0.0.0.0 or ::0 to bind to all addresses.
 * @param port The port to bind to.
 * @return The socket we've bound to. If no socket could be bound, just exit.
 */
int bind_listen_sock(const char *host, const unsigned short port);

/**
 * @brief Resolves a remote host into a struct sockaddr
 *
 * This is meant for remote hosts, don't use this to resolve a local
 * address to listen on.
 * @param host The hostname to resolve, though it can be an IP address too.
 * @param port The port of the service to connect to.
 * @param addr[out] We put the resolved info in to here. Make sure there's
 *        enough space in it, we'll assume the underlying allocated type is
 *        `struct sockaddr_storage`.
 * @param len[out] The length of the socket address written to addr.
 * @return TPX_FAILURE on failure or TPX_SUCCESS on success
 */
tpx_err_t get_conn(const char *host, const unsigned short port,
                   struct sockaddr *addr, socklen_t *len);

#endif
