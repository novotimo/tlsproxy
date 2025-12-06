#ifndef __TLSPROXY_ERRORS_H
#define __TLSPROXY_ERRORS_H

#define TPX_SUCCESS 0 /**< For successful function returns */
#define TPX_FAILURE 1 /**< For failed functions, non-recoverable */
#define TPX_AGAIN   2 /**< For functions which would block */
#define TPX_CLOSED  3 /**< This function closed the proxy/connection */
#define TPX_EMPTY   10 /**< Error return for reading from empty queues */

typedef int tpx_err_t;

#endif
