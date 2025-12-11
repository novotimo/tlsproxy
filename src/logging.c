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


void write_logs(int logfd, logger_t *logger, uint64_t evt_count) {
    if (!logger->enabled)
        errx(EXIT_FAILURE,
             "Somehow write_logs was called when logging was disabled");
    
    int wrapped = logger->write_idx < logger->read_idx;

    for (int i=0; i<evt_count; ++i) {
        // Invariants
        assert(logger->read_idx < TPX_LOGBUF_SIZE);
        assert(logger->write_idx < TPX_LOGBUF_SIZE);
        if (logger->read_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        if (logger->write_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        
        // This length includes the current byte.
        size_t len_to_end = TPX_LOGBUF_SIZE - logger->read_idx;
        size_t len_to_check = wrapped ? len_to_end : logger->write_idx;
        size_t linelen = strnlen(&logger->log_buf[logger->read_idx],
                                 len_to_check);
        ssize_t retcode = write(logfd, &logger->log_buf[logger->read_idx],
                                linelen);
        if (retcode == -1) {
            // We don't want to crash here
            perror("Writing log failed");
            return;
        }

        logger->read_idx += linelen + 1;
        if (logger->read_idx == TPX_LOGBUF_SIZE)
            logger->read_idx = 0;

        // If we need to wrap around
        if (wrapped && linelen == len_to_end) {
            linelen = strnlen(&logger->log_buf[0], logger->write_idx);
            retcode = write(logfd, &logger->log_buf[logger->read_idx], linelen);
            if (retcode == -1) {
                perror("Writing log failed");
                return;
            }
            logger->read_idx = linelen + 1;
        }
        // So what if this fails
        write(logfd, "\n", 1);

        // Invariants
        assert(logger->read_idx < TPX_LOGBUF_SIZE);
        assert(logger->write_idx < TPX_LOGBUF_SIZE);
        if (logger->read_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
        if (logger->write_idx > 0)
            assert(logger->log_buf[logger->read_idx-1] == '\0');
    }
}

void log_msg(logger_t *logger, const char *fmt, ...) {
    static char logstr[TPX_LOGBUF_SIZE-1];
    if (pthread_mutex_lock(&logger->write_lock)) {
        perror("pthread_mutex_lock when logging");
        return;
    }
        
    va_list va;
    va_start(va, fmt);
    int nwritten = vsnprintf(logstr, sizeof(logstr), fmt, va);
    va_end(va);

    // If the log got truncated by vsnprintf
    if (nwritten > TPX_LOGBUF_SIZE-1)
        nwritten = TPX_LOGBUF_SIZE-1;

    if (logger->write_idx + nwritten > TPX_LOGBUF_SIZE) {
        memcpy(&logger->log_buf[logger->write_idx],
               logstr, TPX_LOGBUF_SIZE - logger->write_idx);
        memcpy(&logger->log_buf[0],
               &logstr[TPX_LOGBUF_SIZE - logger->write_idx],
               nwritten - (TPX_LOGBUF_SIZE - logger->write_idx));
        logger->write_idx = nwritten - (TPX_LOGBUF_SIZE-logger->write_idx) + 1;
    } else {
        memcpy(&logger->log_buf[logger->write_idx], logstr, nwritten);
        logger->write_idx += nwritten + 1;
        if (logger->write_idx == TPX_LOGBUF_SIZE)
            logger->write_idx = 0;
    }

    // Notify the parent process that we're ready to go
    uint64_t count=1;
    write(logger->eventfd, &count, sizeof(count));
        
    pthread_mutex_unlock(&logger->write_lock);
}

void log_ossl(logger_t *logger, const char *desc) {
    char errbuf[TPX_LOGBUF_SIZE-1];
    BIO *bio = BIO_new_mem_buf(errbuf, TPX_LOGBUF_SIZE-1);
    ERR_print_errors(bio);
    log_msg(logger, "%s: %s", desc, errbuf);
}
