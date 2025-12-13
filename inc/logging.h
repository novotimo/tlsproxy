#ifndef __TLSPROXY_LOGGING_H
#define __TLSPROXY_LOGGING_H


#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>


// TODO: Try various sizes under load
#define TPX_LOGBUF_SIZE 128000
#define TPX_LOG_LINE_MAX 8192


typedef enum loglevel {
    LL_FATAL = 0,
    LL_ERROR = 1,
    LL_WARN  = 2,
    LL_INFO  = 3,
    LL_DEBUG = 4
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
    uint32_t read_idx;
    uint32_t write_idx; /**< @brief The index from which to start writing */
    pthread_mutex_t write_lock; /**< @brief One at a time, workers */
    char log_buf[TPX_LOGBUF_SIZE]; /**< @brief A ring buffer containing log
                                      messages to write */
} logger_t;

// For master process
void write_logs(int logfd, logger_t *logger, uint64_t evt_count);
void m_log_msg(int logfd, loglevel_t level, const char *fmt, ...);
void m_log_fatal(int logfd, const char *description, int has_errno);
void m_log_ossl(int logfd, loglevel_t level, const char *description);
void m_log_errno(int logfd, loglevel_t level, const char *description);

// For worker processes
void log_msg(loglevel_t level, const char *fmt, ...);
void log_fatal(const char *description, int has_errno);
void log_ossl(loglevel_t level, const char *description);
void log_errno(loglevel_t level, const char *description);

// Sanitize characters one by one, but stop if we reach endptr
int sanitize_c(const char c, char *outptr, const char *endptr);

/* Internal functions */

int _ringbuf_fits(logger_t *logger, uint32_t len);

#endif
