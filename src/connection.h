#ifndef __TLSPROXY_CONNECTION_H
#define __TLSPROXY_CONNECTION_H

#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "errors.h"
#include "queue.h"

/*********************************************
 * Defines
 ********************************************/

#define TPX_NET_BUFSIZE 16384

#define DO_READ(ssl, fd, buf, bufsize) \
    ssl ? SSL_read(ssl,buf,bufsize) : read(fd,buf,bufsize)

#define DO_SEND(ssl, fd, buf, bufsize) \
    ssl ? SSL_write(ssl,buf,bufsize) :send(fd,buf,bufsize,0)

/*********************************************
 * Structs
 ********************************************/

/** Connection context wrapping a single socket with optional TLS */
typedef struct connection_s {
    int fd;

    /** The buffer queue for data coming in from the peer. */
    queue_t *in_bufq;

    /** The buffer queue for data to write to the peer. Can be the same ptr as the
        in_bufq */
    queue_t *out_bufq;

    /**
     * Different meaning based on socket type.
     * For listen sockets, this is the destination address to forward
     * requests to. For connection sockets, this is the address to
     * connect to. For accepted sockets, this is the peer host from
     * which the connection was accepted.
     */
    struct sockaddr_storage peer_addr;

    SSL *ssl;

    /**
     * Handle a read operation by reading it (decrypted if needed)
     * into the read buffer, chunking it, and pushing the chunks to
     * the queue.
     */
    tpx_err_t (*handle_read)(struct connection_s *conn);
    
    /**
     * Handle writing, and flushing data when the first write wasn't
     * enough, encrypting if required.
     */
    tpx_err_t (*handle_write)(struct connection_s *conn);
    
    /**
     * Process the data received
     */
    tpx_err_t (*handle_process)(struct connection_s *conn);
    
    /**
     * Handle accepting a connection and putting it on another socket.
     */
    struct connection_s *(*handle_accept)(struct connection_s *conn,
                                          SSL_CTX *ssl_ctx,
                                          queue_t *in_bufq, queue_t *out_bufq);
    
    /**
     * Handle accepting a connection and putting it on another socket.
     */
    void (*handle_close)(struct connection_s *conn);
    int closed;

} connection_t;


/*********************************************
 * Prototypes
 ********************************************/
/**
 * @brief Handles all pending events on the connection
 *
 * @param conn The connection context
 * @param events The epoll events ready on the socket
 */
tpx_err_t tpx_handle_all(connection_t *conn, int epollfd, uint32_t events,
                         SSL_CTX *ssl_ctx);

/**
 * @brief Closes the connection.
 *
 * Closes the connection, cleaning up the connection using its
 * close callback, closing sockets, freeing buffers, and removing
 * the socket from the epoll list.
 */
void tpx_conn_close(connection_t *conn, int epollfd);

tpx_err_t tpx_handle_read(connection_t *conn);
tpx_err_t tpx_handle_write(connection_t *conn);
tpx_err_t tpx_handle_process(connection_t *conn);
void tpx_handle_close(connection_t *conn);

/**
 * @brief Accepts a TLS connection.
 *
 * @param in_bufq The buffer queue for data accepted from the client.
 * @param out_bufq The buffer queue for data to send to the client.
 */
connection_t *tpx_handle_accept(connection_t *conn, SSL_CTX *ssl_ctx,
                                queue_t *in_bufq, queue_t *out_bufq);


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
                                socklen_t addrlen, SSL_CTX *ctx,
                                queue_t *in_bufq, queue_t *out_bufq);

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
