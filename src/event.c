#include "event.h"

#include <err.h>

#include "listen.h"
#include "proxy.h"

tpx_err_t dispatch_events(event_t *ev, int epollfd, uint32_t events,
                          void *ssl_ctx, unsigned int conn_timeout) {
    uint8_t tag = (uintptr_t)ev & 0x3;
    ev = (event_t *)((uintptr_t)ev - tag);
    switch (ev->event_id) {
    case EV_LISTEN:
        return handle_accept((listen_t *)ev, epollfd, events, ssl_ctx,
                             conn_timeout);
    case EV_PROXY:
        return handle_proxy((proxy_t *)ev, epollfd, events, ssl_ctx, tag,
                            conn_timeout);
    default:
        errx(EXIT_FAILURE, "Got unexpected event on dispatching: %d",
             ev->event_id);
    }
}
