#ifndef __TLSPROXY_LOGGING_H
#define __TLSPROXY_LOGGING_H


#include <stdint.h>
#include <pthread.h>
#include <openssl/x509.h>


// TODO: Try various sizes under load
#define TPX_LOGBUF_SIZE 65535
#define TPX_LOG_LINE_MAX 8192
#define TPX_LOG_ARGV_MAX 256
#define TPX_IPV6_MAXLEN 46

#define TPX_ERR_PLAIN 0
#define TPX_ERR_ERRNO 1
#define TPX_ERR_OSSL  2

#define TPX_WORKER_DEAD 1
#define TPX_WORKER_ALIVE 1


// Audit events
#define STARTUP_EVENT "startup"
#define WORKER_EVENT "worker"
#define CONFIG_LOAD_EVENT "config_loaded"
#define LISTEN_EVENT "listen"
#define CERT_LOAD_EVENT "cert_loaded"
#define ERR_EVENT "system_error"
#define SIGNAL_EVENT "signal_received"
#define PROXY_EVENT "proxy"
#define HANDSHAKE_EVENT "handshake"


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

typedef struct tpx_config_s tpx_config_t;
struct signalfd_siginfo;
typedef struct proxy_s proxy_t;
typedef struct listen_s listen_t;


// For master process
void write_logs(int logfd, logger_t *logger, uint64_t evt_count);

// Message schemas (Master). _m refers to master versions of functions
void log_startup(int logfd, loglevel_t level, int argc, char *argv[]);
void log_worker(int logfd, loglevel_t level, int worker_state,
                pid_t worker_pid, int wstatus);
void log_config_load(int logfd, loglevel_t level, const tpx_config_t *config);
void log_cert_load(int logfd, loglevel_t level, X509 *cert, int is_client);
void log_system_err_m(int logfd, loglevel_t level, const char *msg,
                      int errtype);
void log_system_err_m_ex(int logfd, loglevel_t level, const char *msg,
                       const char *desc);
void log_signal_m(int logfd, loglevel_t level, struct signalfd_siginfo *si);

// Message schemas (Workers)
void log_system_err(loglevel_t level, const char *msg, int errtype);
void log_signal(loglevel_t level, struct signalfd_siginfo *si);
// If desc is null it get the OpenSSL error queue instead
void log_proxy(loglevel_t level, proxy_t *proxy, const char *subevent,
               const char *msg, const char *desc);
void log_listen(loglevel_t level, listen_t *listener);
void log_handshake(loglevel_t level, proxy_t *proxy, const char *outcome);


#endif
