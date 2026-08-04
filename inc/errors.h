#ifndef __TLSPROXY_ERRORS_H
#define __TLSPROXY_ERRORS_H

#define TPX_SUCCESS 0 /**< For successful function returns */
#define TPX_FAILURE 1 /**< For failed functions, non-recoverable */
#define TPX_AGAIN   2 /**< For functions which would block */
#define TPX_CLOSED  3 /**< This function closed the proxy/connection */
#define TPX_EMPTY   10 /**< Error return for reading from empty queues */

typedef int tpx_err_t;

/* static, not a bare `inline`: a C99 inline definition emits no external
 * symbol, so at -O0 every call that is not inlined is an undefined reference.
 * Release (-O2) inlines them all and links clean, which would have left this
 * broken in Debug and CI only. */
static inline int error_rc_bad(tpx_err_t error) {
    return error == TPX_FAILURE
        || error == TPX_CLOSED
        || error == TPX_EMPTY;
}

#endif
