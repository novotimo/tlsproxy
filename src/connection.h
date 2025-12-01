#ifndef __TLSPROXY_CONNECTION_H
#define __TLSPROXY_CONNECTION_H

#include <sys/socket.h>

#include <openssl/ssl.h>

#include "queue.h"

/*********************************************
 * Structs
 ********************************************/

/** Connection context wrapping a single socket with optional TLS */
typedef struct connection_s {
    int fd;

    /** The read-write buffer: data is read into this and then written
        from it in a FIFO manner */
    queue_t *rw_bufs;
    /** The cursor within the first buffer (if not all data could be
        sent at once) */
    unsigned int buf_index;

    /**
     * Different meaning based on socket type.
     * For listen sockets, this is the destination address to forward
     * requests to. For connection sockets, this is the address to
     * connect to. For accepted sockets, this is the peer host from
     * which the connection was accepted.
     */
    struct sockaddr_storage peer_addr;
    /** Different meaning based on socket type, see peer_addr */
    unsigned short peer_port;

    SSL *ssl_ctx;

    void (*handle_read)(struct connection_s *conn);
    void (*handle_write)(struct connection_s *conn);
    void (*handle_timeout)(struct connection_s *conn);

} connection_t;


/*********************************************
 * Prototypes
 ********************************************/

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
connection_t *tpx_create_listener(const char *host,
                                  const unsigned short port);

// TODO: make another version of this for accepting TLS connections
/**
 * @brief Makes a connection ctx for an accepted socket.
 *
 * Creates a connection ctx for an accepted socket. Does not call
 * accept.
 * @param conn_sock The socket which was just accepted.
 * @param addr The address of the remote host as returned by accept().
 * @param addrlen The length of the address the remote host returned.
 * @return The connection context created.
 */
connection_t *tpx_create_accept(int conn_sock, struct sockaddr *addr,
                                socklen_t addrlen);

/**
 * @brief Makes a connection ctx for a connect socket.
 *
 * Creates a connection ctx for a connection socket, first creating
 * the socket based on the addr, setting it to nonblocking mode,
 * and then starting the connection.
 *
 * PS. This takes a sockaddr to connect because we only want to
 * resolve the name once.
 * @param addr A pointer to the socket address to connect to.
 * @param
 */
connection_t *tpx_create_connect(struct sockaddr *addr,
                                 socklen_t addrlen);

#endif
