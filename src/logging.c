#include "logging.h"


#include <assert.h>
#include <err.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#include "shmem.h"


shared_t *g_shmem;


#define INC_WRAP(IDX) \
    (IDX + 1 >= TPX_LOGBUF_SIZE) ? IDX = 0 : IDX++


// Returns the new write index
uint64_t _log_str(const char *str, size_t len, uint64_t w_idx);
int _log_str_cb(const char *str, size_t len, void *u);


void write_logs(int logfd, logger_t *logger, uint64_t evt_count) {
    if (!logger->enabled)
        errx(EXIT_FAILURE,
             "Somehow write_logs was called when logging was disabled");

    for (int i=0; i<evt_count; ++i) {
        // To make sure my invariants hold, make sure write_idx doesn't change
        // during loop
        uint64_t w_idx = logger->write_idx;
        int wrapped = w_idx < logger->read_idx;
        
        // Invariants
        assert(logger->read_idx < TPX_LOGBUF_SIZE);
        assert(w_idx < TPX_LOGBUF_SIZE);
        if (logger->read_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        if (w_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        
        // This length includes the current byte.
        size_t len_to_end = TPX_LOGBUF_SIZE - logger->read_idx;
        size_t len_to_check = wrapped ? len_to_end : w_idx;
        size_t linelen = strnlen(&logger->log_buf[logger->read_idx],
                                 len_to_check);
        ssize_t retcode = write(logfd, &logger->log_buf[logger->read_idx],
                                linelen);
        if (retcode == -1) {
            // We don't want to crash here
            perror("Writing log failed");
            return;
        }

        logger->read_idx += linelen;
        if (logger->read_idx >= TPX_LOGBUF_SIZE)
            logger->read_idx = 0;

        // If we need to wrap around
        if (wrapped && linelen == len_to_end) {
            linelen = strnlen(&logger->log_buf[0], w_idx);
            retcode = write(logfd, &logger->log_buf[logger->read_idx], linelen);
            if (retcode == -1) {
                perror("Writing log failed");
                return;
            }
            logger->read_idx = linelen;
        }
        
        // Skip the null byte
        assert(logger->log_buf[logger->read_idx] == '\0');
        INC_WRAP(logger->read_idx);
        
        // Invariants
        assert(logger->read_idx < TPX_LOGBUF_SIZE);
        assert(w_idx < TPX_LOGBUF_SIZE);
        if (logger->read_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        if (w_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
    }
}

// Doesn't write null byte
uint64_t _log_str(const char *str, size_t len, uint64_t w_idx) {
    logger_t *logger = &g_shmem->logger;
    
    if (w_idx + len > TPX_LOGBUF_SIZE) {
        // Wrap the message around the ring buffer
        memcpy(&logger->log_buf[w_idx],
               str, TPX_LOGBUF_SIZE - w_idx);
        memcpy(&logger->log_buf[0],
               &str[TPX_LOGBUF_SIZE - w_idx],
               len - (TPX_LOGBUF_SIZE - w_idx));
        w_idx = len - (TPX_LOGBUF_SIZE-w_idx);
    } else {
//        fprintf(stderr, "Writing %lu bytes to log_buf[%lu]\n", len, w_idx);
        memcpy(&logger->log_buf[w_idx], str, len);
//        fprintf(stderr, "New str is %s\n", &logger->log_buf[w_idx]);
        w_idx += len;
        if (w_idx == TPX_LOGBUF_SIZE)
            w_idx = 0;
    }
    
    return w_idx;
}

// This keeps updating the write index until we are left with the final one
int _log_str_cb(const char *str, size_t len, void *w_idx) {
//    fprintf(stderr, "in _log_str_cb('%s', %lu, %lu)\n", str, len, *(uint64_t *)w_idx);
    *(uint64_t *)w_idx = _log_str(str, len, *(uint64_t *)w_idx);
    return 1;
}

void log_msg(loglevel_t level, const char *fmt, ...) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;
    
    static char logstr[TPX_LOGBUF_SIZE-1];
    va_list va;
    va_start(va, fmt);
    int nwritten = vsnprintf(logstr, sizeof(logstr), fmt, va);
    va_end(va);

    // If the log got truncated by vsnprintf, just write the truncated stuff
    if (nwritten > TPX_LOGBUF_SIZE-1)
        nwritten = TPX_LOGBUF_SIZE-1;

    if (pthread_mutex_lock(&logger->write_lock)) {
        perror("pthread_mutex_lock when logging");
        return;
    }

    uint64_t w_idx = _log_str(logstr, nwritten, logger->write_idx);

    logger->log_buf[w_idx] = '\n';
    INC_WRAP(w_idx);
    logger->log_buf[w_idx] = '\0';
    INC_WRAP(w_idx);
    logger->write_idx = w_idx;
    
    pthread_mutex_unlock(&logger->write_lock);

    // Notify the parent process that we're ready to go
    uint64_t count=1;
    write(logger->eventfd, &count, sizeof(count));
}


void log_ossl(loglevel_t level, const char *description) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    if (pthread_mutex_lock(&logger->write_lock)) {
        perror("pthread_mutex_lock when logging");
        return;
    }

    uint64_t w_idx = _log_str(description, strlen(description),
                              logger->write_idx);
    const char extra[] = ": printing OpenSSL error queue:\n";
    w_idx = _log_str(extra, strlen(extra), w_idx);

    ERR_print_errors_cb(_log_str_cb, &w_idx);
    
    logger->log_buf[w_idx++] = '\0';
    INC_WRAP(w_idx);
    
    logger->write_idx = w_idx;
    
    pthread_mutex_unlock(&logger->write_lock);
    
    // Notify the parent process that we're ready to go
    uint64_t count=1;
    write(logger->eventfd, &count, sizeof(count));
}

void log_err(loglevel_t level, const char *description) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    fprintf(stderr, "Errno is %d, strerror shows '%s'\n", errno, strerror(errno));
    log_msg(level, "%s: %s", description, strerror(errno));
}
