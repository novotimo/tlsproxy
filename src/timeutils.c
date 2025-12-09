#include "timeutils.h"

#include <stdint.h>
#include <time.h>

/* "Borrowed" from nginx's ngx_times.c          *
 * See their copyright in external/ngx_rbtree.c */
uint64_t gettime() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t sec = ts.tv_sec;
    uint64_t msec = ts.tv_nsec / 1000000;
    return sec * 1000 + msec;
}

int timeout_expired(uint64_t expiring) {
    return (int64_t) (expiring - gettime()) < 0;
}
