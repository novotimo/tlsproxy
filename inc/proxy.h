#ifndef __TLSPROXY_PROXY_H
#define __TLSPROXY_PROXY_H

#include <limits.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <sys/socket.h>

#include "errors.h"
#include "ngx_rbtree.h"
#include "queue.h"


#define TPX_NET_BUFSIZE 16384 /**< @brief The buffer chunk size in the bufq */
_Static_assert(TPX_NET_BUFSIZE < INT_MAX, "TPX_NET_BUFSIZE must fit into an "
               "int without truncation as it's used with SSL_{write,read}");

#define DO_READ(ssl, fd, buf, bufsize) \
    is_client ? SSL_read(ssl,buf,bufsize) : read(fd,buf,bufsize)

#define DO_SEND(ssl, fd, buf, bufsize) \
    is_client ? SSL_write(ssl,buf,bufsize) : send(fd,buf,bufsize,0)


extern ngx_rbtree_t timeouts;


/** @brief The proxy state, what else needs to be said? */
typedef enum proxy_state_e {
    PS_CLIENT_CONNECTED, /**< @brief Client is connected, try connect to serv */
    PS_SERVER_CONNECTING, /**< @brief Client is connected, serv connect request
                           * pending */
    PS_READY, /**< @brief Both client and server are ready to rumble */

    /* Right now there are two timeout types, a connect timeout and a
     * shutdown timeout. If the state is earlier than this comment, it's
     * treated as a connect timeout, and if the state is later (starting
     * with SERVER_DISCONNECTED), it's treated as a shutdown timeout.
     * If you want to make a new type of timeout, edit proxy_handle_timeout()
     */

    PS_SERVER_DISCONNECTED, /**< @brief Server disconnected, pending client
                             * disconnect (it needs to await SSL_shutdown) */
    PS_CLIENT_FLUSHED, /**< @brief All pending data has been flushed to the
                        * client, so we can now send our close_notify */
    PS_CLOSE_NOTIFY_SENT, /**< @brief We've sent our close_notify, so all we
                           * need to do is set our linger timer and wait for the
                           * client to die so we can gracefully shut down */
    PS_CLIENT_DISCONNECTED, /**< @brief Client disconnected, so what it already
                             * sent still has to reach the server before we
                             * half-close that leg */
    PS_SERVER_FLUSHED /**< @brief All pending data has been flushed to the
                       * server and our FIN is sent, so the only thing left is
                       * to read what the server still owes the client */
} proxy_state_t;

typedef struct listen_s listen_t;

/**
 * @brief The data structure shared between both fds of a proxy tunnel.
 *
 * This proxy_s is the event context that holds all info for the proxy.
 * In the effort to deduplicate data, this same structure is assigned
 * to both sockets in the proxy pair. But how can we distinguish
 * which socket an event that we receive from epoll refers to? Well, using
 * tagged pointers of course: if ptr & 1 == 1, it's an event on the client
 * fd, and if ptr & 1 == 0, it's on the server fd.
 *
 * To find out if the timer is set, just look at the state. The timer is only
 * set in the PS_SERVER_CONNECTING state.
 */
typedef struct proxy_s {
    uint8_t event_id; /**< @brief EV_PROXY */

    bufq_t *c2s; /**< @brief The client-to-server buffer queue */
    bufq_t *s2c; /**< @brief The server-to-client buffer queue */

    int client_fd; /**< @brief The client file descriptor.
                    * It must be set to -1 once closed */
    int serv_fd; /**< @brief The client file descriptor.
                    * It must be set to -1 once closed */

    listen_t *listener;

    struct sockaddr_storage client_addr; /**< @brief Addr of client */
    socklen_t client_addrlen; /**< @brief Length of client_addr */
    
    ngx_rbtree_node_t timer; /**< @brief The time when this event expires */
    uint64_t conn_timeout; /**< @brief The amout of time a proxy has
                            * to connect to the backend */
    uint64_t shutdown_time; /**< @brief The time when a proxy definitely has
                             * to shut down */
    uint64_t shutdown_timeout; /**< @brief The amout of time a proxy has
                                * to shut down before it's forced to */
    uint64_t shutdown_interval; /**< @brief The amount of time between client
                                 * messages that needs to elapse after the
                                 * server socket is shut down before we
                                 * shut down the client connection */
    
    SSL *ssl; /**< @brief The SSL session context */

    unsigned int timer_set : 1;
    unsigned int hand_shaken : 1; /**< @brief Whether the handshake is done */
    unsigned int client_notified_close : 1; /**< @brief whether our client
                                             * sent us a close_notify */
    
    proxy_state_t state; /**< @brief The current proxy state */
} proxy_t;


/**
 * @brief Handle a proxy event.
 *
 * Handles a proxy event by first checking the proxy state. If we're
 * initializing (PS_CLIENT_CONNECTED or PS_SERVER_CONNECTING), start connecting
 * or keep trying to connect. If either side has disconnected, shut down the
 * proxy. Otherwise, if we're in the PS_READY state, do the following:
 * 
 * If we're on the client fd, we flush the pending data from the s2c bufq
 * to the client first (after encrypting it with TLS), then read into the
 * TLS context with OpenSSL and write the decrypted data into the c2s bufq.
 *
 * If we're on the server fd, we just flush the plain data from c2s and then
 * read into s2c.
 * @param proxy The proxy context received from epoll.
 * @param epollfd The epoll fd, used to add or delete events.
 * @param events The epoll events to handle, such as EPOLLIN, AND'd together.
 * @param ssl_ctx The SSL_CTX which we use to make new TLS sessions.
 * @param tag The tag on the event pointer. For now, a tag of 1 means this
 *        is a client connection, and 0 means it's a server connection.
 * @return The outcome of handling the event, either TPX_SUCCESS, TPX_FAILURE,
 *         or TPX_CLOSED (which indicates that the proxy_t is freed).
 */
tpx_err_t handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                       uint8_t tag);
/**
 * @brief Create a proxy, put a connect socket in, and wait for connect.
 * @param accepted_fd The fd that we just received from a call to accept().
 * @param listen The context of the listen socket, as returned from epoll.
 * @param ssl The initialized SSL session context.
 * @param server_addr The server address which the connect socket should
 *        connect to.
 * @param server_addrlen The address length of server_addr.
 * @return A pointer to a valid proxy_t if successful, NULL if not.
 */
proxy_t *create_proxy(int accepted_fd, SSL *ssl,
                      listen_t *listener,
                      uint64_t conn_timeout,
                      int keepidle, int keepintvl, int keepcnt,
                      uint64_t shutdown_timeout, uint64_t shutdown_interval);

/**
 * @brief Add client and server sockets of proxy to epoll.
 * @param proxy The proxy containing two valid sockets.
 * @param epollfd The epoll file descriptor
 * @return TPX_FAILURE on failure, TPX_SUCCESS on success.
 */
tpx_err_t proxy_add_to_epoll(proxy_t *proxy, int epollfd);

/**
 * @brief Continue on with connecting to the server.
 *
 * Run this once after the connect socket is made to begin the connection.
 * Wait for an EPOLLOUT event on the connect socket fd and run this again,
 * and it should just connect.
 * @param proxy The proxy containing the server fd
 * @return TPX_FAILURE on failure, TPX_AGAIN when we need to run this again
 *         (it would block), and TPX_SUCCESS when the connection is complete.
 */
tpx_err_t proxy_handle_connect(proxy_t *proxy, uint64_t conn_timeout);

/**
 * @brief Handle a read from the client or server socket.
 * @param proxy The proxy to read data into
 * @param is_client If this is 1, communicate with TLS to client. If it's 0,
 *        communicate in plaintext with the server.
 * @return TPX_FAILURE on failure and TPX_SUCCESS on success.
 */
tpx_err_t proxy_handle_read(proxy_t *proxy, int is_client);

/**
 * @brief Handle a read from the client or server socket, sending the
 *        received data to Narnia.
 * @param proxy The proxy to read data into
 * @param is_client If this is 1, communicate with TLS to client. If it's 0,
 *        communicate in plaintext with the server.
 * @return TPX_FAILURE on failure and TPX_SUCCESS on success.
 */
tpx_err_t proxy_ignore_read(proxy_t *proxy, int is_client);

/**
 * @brief Handle a write to the client or server socket.
 * @param proxy The proxy to write data from
 * @param is_client If this is 1, communicate with TLS to client. If it's 0,
 *        communicate in plaintext with the server.
 * @return TPX_FAILURE on failure and TPX_SUCCESS on success.
 */
tpx_err_t proxy_handle_write(proxy_t *proxy, int is_client);

/**
 * @brief Used to do some action after a read event.
 *
 * Currently, if we get a read event on one socket, we run proxy_handle_write()
 * on the other socket, either queueing or sending data.
 * @param proxy The proxy to process the data of
 * @param is_client Set this to 1 if you've just read the client socket, and
 *        0 otherwise.
 * @return TPX_FAILURE on failure and TPX_SUCCESS on success.
 */
tpx_err_t proxy_process_data(proxy_t *proxy, int is_client);

/**
 * @brief Used to either completely close a proxy or initiate graceful shutdown.
 * @param proxy The proxy to shut down. This will be freed.
 * @param epollfd The epoll fd, used to delete the proxy from epoll.
 */
void proxy_close(proxy_t *proxy, int epollfd);

/** @brief Create a nonblocking socket to connect to. */
int create_connect(proxy_t *proxy, int keepidle, int keepintvl, int keepcnt);

/** @brief Do we have any queued data to send? */
int outbuf_empty(proxy_t *proxy, int is_client);

/** @brief Init the timeout rbtree */
void proxy_init_timeouts(void);

/** @brief Handle the proxy getting a timeout. */
void proxy_handle_timeout(proxy_t *proxy, int epollfd);

tpx_err_t proxy_handle_ssl_failure(proxy_t *proxy, int retcode);

#endif
