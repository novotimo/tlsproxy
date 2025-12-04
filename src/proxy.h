#ifndef __TLSPROXY_PROXY_H
#define __TLSPROXY_PROXY_H

#include "connection.h"

/*********************************************
 * Enums and Structs
 ********************************************/

typedef enum proxy_state_e {
    PS_CLIENT_CONNECTED,
    PS_READY,
    PS_SERVER_DISCONN,
    PS_DONE
} proxy_state_t;

typedef struct proxy_s {
    /** The encrypted client connection */
    connection_t *enc;
    /** The plaintext server connection */
    connection_t *plain;

    proxy_state_t state;
} proxy_t;


/*********************************************
 * Prototypes
 ********************************************/

tpx_err_t tpx_proxy_handle_all(connection_t *conn, int epollfd,
                               uint32_t events, SSL_CTX *ssl_ctx);
connection_t *tpx_proxy_listen(const char *lhost, const unsigned short lport,
                               const char *thost, const unsigned short tport);
connection_t *tpx_proxy_accept(connection_t *listen_conn, SSL_CTX *ssl_ctx,
                               queue_t *in_bufq, queue_t *out_bufq);
tpx_err_t tpx_proxy_handle_connect(connection_t *conn);
tpx_err_t tpx_proxy_server_process(connection_t *conn);
tpx_err_t tpx_proxy_client_process(connection_t *conn);

void tpx_proxy_close(connection_t *conn, int epollfd);



#endif
