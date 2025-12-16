#ifndef __TLSPROXY_EVENT_H
#define __TLSPROXY_EVENT_H

#include <openssl/ssl.h>
#include <stdint.h>

#include "errors.h"


/** @brief The ID of the event, used to distinguish them. */
typedef enum event_id_s {
    EV_LISTEN, /**< @brief Event is a listen_t */
    EV_PROXY /**< @brief Event is a proxy_t */
} event_id_t;

/** @brief This struct is common to all events. */
typedef struct event_s {
    uint8_t event_id; /**< @brief Identifies which event type to cast */
} event_t;


/**
 * @brief Dispatches all events on an fd until we would start blocking.
 *
 * @param ev The event returned from epoll_wait()
 * @param epollfd The epoll fd.
 * @param events The event flags returned by epoll, such as EPOLLIN.
 * @param ssl_ctx The SSL_CTX from OpenSSL. It's a void* here to keep us from
 *        needing to import OpenSSL into this header.
 * @return The outcome of handling the event, either TPX_SUCCESS, TPX_FAILURE,
 *         or TPX_CLOSED (which indicates that the event data is freed).
 */
tpx_err_t dispatch_events(event_t *ev, int epollfd, uint32_t events);

#endif
