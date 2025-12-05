#ifndef __TLSPROXY_EVENT_H
#define __TLSPROXY_EVENT_H

#include <stdint.h>


typedef enum event_id_s {
    EV_LISTEN,
    EV_PROXY
} event_id_t;

typedef struct event_s {
    uint8_t event_id;
} event_t;


void dispatch_events(event_t *ev, int epollfd, uint32_t events,
                          void *ssl_ctx);

#endif
