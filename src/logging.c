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


typedef struct linebuf_s {
    uint32_t len;
    char buf[TPX_LOG_LINE_MAX+1];
} linebuf_t;

shared_t *g_shmem;


#define INC_WRAP(IDX) \
    (IDX + 1 >= TPX_LOGBUF_SIZE) ? IDX = 0 : IDX++


// Returns the new write index
int _linebuf_add_metadata(linebuf_t *linebuf, int is_master);
int _linebuf_append(linebuf_t *linebuf, const char *str, size_t len,
                   int sanitize);
int _linebuf_append_cb(const char *str, size_t len, void *u);
uint64_t _log_str(const char *str, size_t len, linebuf_t *linebuf);


// This runs on the master process only
void write_logs(int logfd, logger_t *logger, uint64_t evt_count) {
    if (!logger->enabled)
        errx(EXIT_FAILURE,
             "Somehow write_logs was called when logging was disabled");

    for (int i=0; i<evt_count; ++i) {
        // Make sure our write index doesn't change during loop
        uint64_t w_idx = logger->write_idx;
        int wrapped = w_idx < logger->read_idx;
        
        // Invariants
        assert(logger->read_idx < TPX_LOGBUF_SIZE);
        assert(w_idx < TPX_LOGBUF_SIZE);
        if (logger->read_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        if (w_idx > 0)
            assert(logger->log_buf[w_idx-1] == '\0');
        
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
            assert(logger->log_buf[w_idx-1] == '\0');
    }
}

int _linebuf_append(linebuf_t *linebuf, const char *str, size_t len,
                    int sanitize) {
    assert(linebuf->len < TPX_LOG_LINE_MAX);

    if (sanitize) {
        char *sanitized = linebuf->buf;
        // endptrs point to the null terminator
        const char *str_endptr = str+len;
        const char *san_endptr = &sanitized[TPX_LOG_LINE_MAX];
        char *sanptr = sanitized + linebuf->len;

        uint8_t filled = 0;
        for (const char *cursor = str; cursor < str_endptr; ++cursor) {
            if (sanitize_c(*cursor, sanptr, san_endptr) == -1) {
                filled = 1;
                break;
            }
        }

        linebuf->len = sanptr - sanitized;
        if (filled) return -1;
    } else {
        memcpy(linebuf->buf, str, len);
        linebuf->len += len;
    }

    assert(linebuf->len < TPX_LOG_LINE_MAX);
    return 0;
}

const char *_rfc3339_time() {
    static char timebuf[64];
    time_t now = time(NULL);
    struct tm local_time;
    localtime_r(&now, &local_time);
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", &local_time);
    return timebuf;
}

const char *_pid() {
    static char pid[10];
    snprintf(pid, sizeof(pid)-1, "%d", getpid());
    return pid;
}

int _linebuf_add_metadata(linebuf_t *linebuf, int is_master) {
    static char metadata[128];
    size_t len = snprintf(metadata, sizeof(metadata),
                          "%s %s[%s]: ", _rfc3339_time(), _pid(),
                          is_master ? "master" : "worker");
    if (len >= sizeof(metadata))
        len = sizeof(metadata)-1;
    return _linebuf_append(linebuf, metadata, len, 0);
}

// Write a log message from the master process.
void m_log_msg(int logfd, loglevel_t level, const char *fmt, ...) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    static linebuf_t linebuf;
    linebuf.len = 0;
    if (_linebuf_add_metadata(&linebuf, 1) == -1) {
        fprintf(stderr, "Couldn't write metadata to log line!\n");
        return;
    }

    va_list va;
    va_start(va, fmt);
    linebuf.len += vsnprintf(&linebuf.buf[linebuf.len],
                             TPX_LOG_LINE_MAX+1 - linebuf.len, fmt, va);
    va_end(va);
    if (linebuf.len > TPX_LOG_LINE_MAX)
        linebuf.len = TPX_LOG_LINE_MAX;

    linebuf.buf[linebuf.len++] = '\n';

    ssize_t retcode = write(logfd, linebuf.buf, linebuf.len);
    if (retcode == -1) {
        // We don't want to crash here
        perror("Writing log failed");
        return;
    }
}

int _linebuf_append_cb(const char *str, size_t len, void *u) {
    return _linebuf_append((linebuf_t *)u, str, len, 1);
}

void m_log_ossl(int logfd, loglevel_t level, const char *description) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    static linebuf_t linebuf;
    linebuf.len = 0;
    if (_linebuf_add_metadata(&linebuf, 1) == -1) {
        fprintf(stderr, "Couldn't write metadata to log line\n");
        return;
    }
    linebuf.len += snprintf(&linebuf.buf[linebuf.len],
                            TPX_LOG_LINE_MAX+1 - linebuf.len,
                            "%s: OpenSSL error queue: ", description);

    // Ignore truncation
    if (linebuf.len > TPX_LOG_LINE_MAX)
        linebuf.len = TPX_LOG_LINE_MAX;
    
    ERR_print_errors_cb(_linebuf_append_cb, &linebuf);
    // This could overwrite the null terminator, keep that in mind
    linebuf.buf[linebuf.len++] = '\n';
 
    ssize_t retcode = write(logfd, linebuf.buf, linebuf.len);
    if (retcode == -1) {
        // We don't want to crash here
        perror("Writing log failed");
    }
}

void m_log_fatal(int logfd, const char *description, int has_errno) {
    if (has_errno) {
        m_log_errno(logfd, LL_FATAL, description);
        err(EXIT_FAILURE, "%s", description);
    } else {
        m_log_msg(logfd, LL_FATAL, "%s", description);
        errx(EXIT_FAILURE, "%s", description);
    }
}

void m_log_errno(int logfd, loglevel_t level, const char *description) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    m_log_msg(logfd, level, "%s: %s", description, strerror(errno));
}

// The following all run on the worker processes only

// MUST be run inside critical section of logger->write_lock
void _ringbuf_writeln(logger_t *logger, linebuf_t *line) {
    if (!_ringbuf_fits(logger, line->len)) {
        fprintf(stderr, "Ring buffer full, dropping new logs...\n");
        return;
    }
    
    uint32_t w_idx = logger->write_idx;
    
    if (w_idx + line->len > TPX_LOGBUF_SIZE) {
        // Wrap the message around the ring buffer
        memcpy(&logger->log_buf[w_idx],
               line->buf, TPX_LOGBUF_SIZE - w_idx);
        memcpy(&logger->log_buf[0],
               &line->buf[TPX_LOGBUF_SIZE - w_idx],
               line->len - (TPX_LOGBUF_SIZE - w_idx));
        w_idx = line->len - (TPX_LOGBUF_SIZE-w_idx);
    } else {
        memcpy(&logger->log_buf[w_idx], line->buf, line->len);
        w_idx += line->len;
        if (w_idx == TPX_LOGBUF_SIZE)
            w_idx = 0;
    }

    logger->log_buf[w_idx] = '\0';
    INC_WRAP(w_idx);
    
    logger->write_idx = w_idx;
}

void log_msg(loglevel_t level, const char *fmt, ...) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;
    
    static linebuf_t linebuf;
    linebuf.len = 0;
    
    if (_linebuf_add_metadata(&linebuf, 0) == -1) {
        fprintf(stderr, "Couldn't write metadata to log line!\n");
        return;
    }

    va_list va;
    va_start(va, fmt);
    linebuf.len += vsnprintf(&linebuf.buf[linebuf.len],
                             TPX_LOG_LINE_MAX+1 - linebuf.len, fmt, va);
    va_end(va);
    // If the log got truncated by vsnprintf, just write the truncated stuff
    if (linebuf.len > TPX_LOG_LINE_MAX)
        linebuf.len = TPX_LOG_LINE_MAX;

    linebuf.buf[linebuf.len++] = '\n';

    if (pthread_mutex_lock(&logger->write_lock)) {
        perror("pthread_mutex_lock when logging");
        return;
    }

    _ringbuf_writeln(logger, &linebuf);

    pthread_mutex_unlock(&logger->write_lock);

    // Notify the parent process that we're ready to go
    uint64_t count=1;
    write(logger->eventfd, &count, sizeof(count));
}

void log_ossl(loglevel_t level, const char *description) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    static linebuf_t linebuf;
    linebuf.len = 0;
    if (_linebuf_add_metadata(&linebuf, 0) == -1) {
        fprintf(stderr, "Couldn't write metadata to log line!\n");
        return;
    }
    
    linebuf.len += snprintf(&linebuf.buf[linebuf.len],
                            TPX_LOG_LINE_MAX+1 - linebuf.len,
                            "%s: OpenSSL error queue: ", description);

    // Ignore truncation
    if (linebuf.len > TPX_LOG_LINE_MAX)
        linebuf.len = TPX_LOG_LINE_MAX;
    
    ERR_print_errors_cb(_linebuf_append_cb, &linebuf);
    // This could overwrite the null terminator, keep that in mind
    linebuf.buf[linebuf.len++] = '\n';
 
    if (pthread_mutex_lock(&logger->write_lock)) {
        perror("pthread_mutex_lock when logging");
        return;
    }

    _ringbuf_writeln(logger, &linebuf);

    pthread_mutex_unlock(&logger->write_lock);

    // Notify the parent process that we're ready to go
    uint64_t count=1;
    write(logger->eventfd, &count, sizeof(count));
}

void log_fatal(const char *description, int has_errno) {
    if (has_errno) {
        log_errno(LL_FATAL, description);
        err(EXIT_FAILURE, "%s", description);
    } else {
        log_msg(LL_FATAL, "%s", description);
        errx(EXIT_FAILURE, "%s", description);
    }
}

void log_errno(loglevel_t level, const char *description) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    log_msg(level, "%s: %s", description, strerror(errno));
}

// Sanitize characters one by one, but stop if we reach endptr
int sanitize_c(const char c, char *outptr, const char *endptr) {
    // Output at most 2 characters per input character
    if (outptr+1 >= endptr) return -1;

    if (isprint(c)) {
        *outptr++ = c;
    } else {
        switch (c) {
        case '\n':
            *outptr++ = '\\';
            *outptr++ = 'n';
            break;
        case '\\':
            *outptr++ = '\\';
            *outptr++ = '\\';
            break;
        case '\r':
            *outptr++ = '\\';
            *outptr++ = 'r';
            break;
        case '\t':
            *outptr++ = '\\';
            *outptr++ = 't';
            break;
        case '"':
            *outptr++ = '\\';
            *outptr++ = '"';
            break;
        default:
            // If we want to use snprintf we need space for the null byte too
            if (outptr+4 >= endptr) return -1;
            snprintf(outptr, 5, "\\x%02x", (const unsigned char)c);
            *outptr += 4;
            break;
        }
    }
    return 0;
}

/* Internal functions */

int _ringbuf_fits(logger_t *logger, uint32_t len) {
    return(((TPX_LOGBUF_SIZE + logger->read_idx - logger->write_idx - 1)
           % TPX_LOGBUF_SIZE) >= len);
}
