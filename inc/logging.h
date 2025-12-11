#ifndef __TLSPROXY_LOGGING_H
#define __TLSPROXY_LOGGING_H


#include <stdint.h>
#include <pthread.h>


#define TPX_LOGBUF_SIZE 16384


typedef enum loglevel {
    LL_NONE,
    LL_ERROR,
    LL_WARN,
    LL_INFO,
    LL_DEBUG
} loglevel_t;

typedef struct logger_s {
    uint8_t enabled; /**< @brief Whether logging is enabled at all */
    loglevel_t loglevel; /**< @brief The maximum level of messages to log */
    int eventfd; /**< @brief The event fd used to notify the logger process */

     /** @brief The index to read from.
      *
      * The read and write indices will only be equal when there is no data
      * to write. If the buffer is full, read_idx will stop at write_idx-1
      * or read_idx=0 and write_idx=TPX_LOGBUF_SIZE-1
      */
    uint64_t read_idx;
    uint64_t write_idx; /**< @brief The index from which to start writing */
    pthread_mutex_t write_lock; /**< @brief One at a time, workers */
    char log_buf[TPX_LOGBUF_SIZE]; /**< @brief A ring buffer containing log
                                      messages to write */
} logger_t;


void write_logs(int logfd, logger_t *logger, uint64_t evt_count);
void log_msg(logger_t *logger, const char *fmt, ...);
void log_ossl(logger_t *logger, const char *desc);


#endif
