#include "logging.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "listen.h"
#include "proxy.h"
#include "shmem.h"
#include "version.h"


#define LINEBUF_OFFSET sizeof(uint32_t)

// To put into _linebuf_append
#define TPX_MODE_NONE     0
#define TPX_MODE_SANITIZE 1
#define TPX_MODE_HEX      2


typedef struct linebuf_s {
    union {
        uint32_t len;
        char buf[TPX_LOG_LINE_MAX+1];
    } u;
} linebuf_t;

shared_t *g_shmem;


#define INC_WRAP(IDX) \
    (IDX + 1 >= TPX_LOGBUF_SIZE) ? IDX = 0 : IDX++

#define GUARD_APPEND(CALL)                                              \
    if (CALL == -1) {                                                   \
        fprintf(stderr, "Error writing log message (%s:%d): buffer is full\n", \
                __func__, __LINE__);                                    \
        return; \
    }

// Use this one nested inside another append call
#define GUARD_APPEND_(CALL)                                             \
    if (CALL == -1) {                                                   \
        fprintf(stderr, "Error writing log message (%s:%d): buffer is full\n", \
                __func__, __LINE__);                                    \
        return -1; \
    }


// Get static strings containing info for log metadata
const char *_rfc3339_time();
const char *_pid();
const char *strlevel(loglevel_t level);

// Each _linebuf function returns -1 when the buffer is full and 0 otherwise
int _linebuf_append(linebuf_t *linebuf, const char *str, size_t len,
                   int mode);
int _linebuf_putc(linebuf_t *linebuf, const char c);
// This doesn't put spaces around, to add a space before this just add a space
// in front of the key when calling the function
int _linebuf_append_kv(linebuf_t *linebuf, const char *key,
                       const char *value, size_t value_len);
int _linebuf_append_ossl(linebuf_t *linebuf);
int _linebuf_append_cb(const char *str, size_t len, void *u);
int _linebuf_append_hex(linebuf_t *linebuf, const unsigned char *buf);

void _log_system_err(linebuf_t *linebuf, loglevel_t level, const char *msg,
                     int errtype, int is_master);
void _log_signal(linebuf_t *linebuf, loglevel_t level,
                 struct signalfd_siginfo *si, int is_master);
void _write_linebuf(logger_t *logger, linebuf_t *linebuf);
void _write_linebuf_fd(int logfd, linebuf_t *linebuf);

/** @return 1 on success, 0 on failure */
int _ringbuf_fits(logger_t *logger, uint32_t len);

/** @brief Sanitize a single character, but return -1 if we would pass endptr */
int _sanitize_c(const char c, char **outptr, const char *endptr);
/** @brief Convert char to hex */
int _hex_c(const char c, char **outptr, const char *endptr);


/** @return 0 on success, -1 on failure */
int _base_schema(linebuf_t *linebuf, int is_master, loglevel_t level,
                 const char *event);


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
        uint32_t linelen = 0;
        if (len_to_end >= LINEBUF_OFFSET) {
            linelen = *(uint32_t *)&logger->log_buf[logger->read_idx];
            logger->read_idx+=LINEBUF_OFFSET;
        } else {
            union {
                unsigned char b[LINEBUF_OFFSET];
                uint32_t i;
            } u;
            for (int i=0; i<LINEBUF_OFFSET; ++i) {
                u.b[i] = logger->log_buf[logger->read_idx];
                INC_WRAP(logger->read_idx);
            }
            linelen = u.i;
        }
        assert(linelen > LINEBUF_OFFSET && linelen < TPX_LOG_LINE_MAX);
        linelen -= LINEBUF_OFFSET;
        len_to_end -= LINEBUF_OFFSET;
        
        ssize_t nwritten = write(logfd, &logger->log_buf[logger->read_idx],
                                MIN(len_to_end,linelen));
        if (nwritten == -1) {
            // We don't want to crash here
            perror("Writing log failed");
            return;
        }

        logger->read_idx += nwritten;
        if (logger->read_idx >= TPX_LOGBUF_SIZE)
            logger->read_idx = 0;

        // If we need to wrap around
        if (wrapped && nwritten == len_to_end && linelen > len_to_end) {
            size_t remaining = linelen - len_to_end;
            
            assert(logger->read_idx == 0);
            
            nwritten = write(logfd, &logger->log_buf[logger->read_idx],
                remaining);
            if (nwritten == -1) {
                perror("Writing log failed");
                return;
            }
            logger->read_idx = remaining;
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

void log_startup(int logfd, loglevel_t level, int argc, char *argv[]) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    GUARD_APPEND(_base_schema(&linebuf, 1, level, STARTUP_EVENT))

    GUARD_APPEND(_linebuf_append(&linebuf, " argv=\"", sizeof("argv=\"")-1,
                     TPX_MODE_NONE));

    for (int i=1; i<argc; ++i) {
        GUARD_APPEND(_linebuf_append(&linebuf, argv[i], strlen(argv[i]),
                                     TPX_MODE_SANITIZE));
        if (i+1 < argc)
            GUARD_APPEND(_linebuf_putc(&linebuf, ' '))
    }
    GUARD_APPEND(_linebuf_putc(&linebuf, '"'));

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " version", TLSPROXY_VERSION,
                                    sizeof(TLSPROXY_VERSION)-1));

    _write_linebuf_fd(logfd, &linebuf);
}

void log_worker(int logfd, loglevel_t level, int worker_state,
                        pid_t worker_pid) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    GUARD_APPEND(_base_schema(&linebuf, 1, level, WORKER_EVENT));
    
    static char dead[] = "dead";
    static char alive[] = "alive";
    
    char *state = worker_state ? alive : dead;
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " worker_state",
                                    state, strlen(state)));
    
    static char id[12];
    assert(snprintf(id, sizeof(id), "%d", worker_pid) < sizeof(id));
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " worker_pid", id, strlen(id)));

    _write_linebuf_fd(logfd, &linebuf);
}

void log_config_load(int logfd, loglevel_t level, const tpx_config_t *config) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;
    
    GUARD_APPEND(_base_schema(&linebuf, 1, level, CONFIG_LOAD_EVENT));

    // Integers need up to 12 characters
    static char nworkers[9+12];
    snprintf(nworkers, sizeof(nworkers), " nworkers=%d", config->nworkers);
    GUARD_APPEND(_linebuf_append(&linebuf, nworkers, strlen(nworkers),
                                 TPX_MODE_NONE));

    _write_linebuf_fd(logfd, &linebuf);
}

void log_cert_load(int logfd, loglevel_t level, X509 *cert, int is_client) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;
    
    GUARD_APPEND(_base_schema(&linebuf, 1, level, CERT_LOAD_EVENT));

    // Writing cert role

    static char leaf[] = "leaf";
    static char ca[] = "ca";
    static char client_ca[] = "client_ca";
    char *role;

    BASIC_CONSTRAINTS *bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL,
                                             NULL);
    if (!bc || bc->ca == 0)
        role = leaf;
    else if (is_client)
        role = client_ca;
    else
        role = ca;

    BASIC_CONSTRAINTS_free(bc);

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " cert_role", role, strlen(role)));

    // Writing cert fingerprint

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (X509_digest(cert, EVP_sha256(), hash, &hash_len) == 0) {
        fprintf(stderr, "Error hashing cert in logger!\n");
        return;
    }
    GUARD_APPEND(_linebuf_append(&linebuf, " cert_fingerprint=\"",
                                 sizeof(" cert_fingerprint=\"")-1,
                                 TPX_MODE_NONE));

    GUARD_APPEND(_linebuf_append(&linebuf, (char *)hash, hash_len,
                                 TPX_MODE_HEX));
    GUARD_APPEND(_linebuf_putc(&linebuf, '"'));
    
    // Writing cert expiration dates

    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);

    struct tm ctime;
    if (ASN1_TIME_to_tm(not_before, &ctime) == 0) {
        fprintf(stderr, "Error converting cert time in logger!\n");
        return;
    }

    static char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", &ctime);
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " cert_notbefore",
                                    timebuf, strlen(timebuf)));
    
    if (ASN1_TIME_to_tm(not_after, &ctime) == 0) {
        fprintf(stderr, "Error converting cert time in logger!\n");
        return;
    }
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", &ctime);
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " cert_notafter",
                                    timebuf, strlen(timebuf)));
    
    // Writing cert and issuer subjects

    X509_NAME *name = X509_get_subject_name(cert);
    char *subjname = X509_NAME_oneline(name, NULL, 0);
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " cert_subject",
                                    subjname, strlen(subjname)));
    CRYPTO_free(subjname, __FILE__, __LINE__);

    name = X509_get_issuer_name(cert);
    char *issuername = X509_NAME_oneline(name, NULL, 0);
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " cert_issuer",
                                    issuername, strlen(issuername)));
    CRYPTO_free(issuername, __FILE__, __LINE__);
        
    _write_linebuf_fd(logfd, &linebuf);
}

void log_system_err_m(int logfd, loglevel_t level, const char *msg,
                      int errtype) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    _log_system_err(&linebuf, level, msg, errtype, 1);

    _write_linebuf_fd(logfd, &linebuf);
}

void log_system_err_m_ex(int logfd, loglevel_t level, const char *msg,
                      const char *desc) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    GUARD_APPEND(_base_schema(&linebuf, 1, level, ERR_EVENT));

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " error_msg", msg,
                                    strlen(msg)));
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " error_desc", desc,
                                    strlen(desc)));

    _write_linebuf_fd(logfd, &linebuf);
}

void log_system_err(loglevel_t level, const char *msg, int errtype) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;

    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    _log_system_err(&linebuf, level, msg, errtype, 0);

    _write_linebuf(logger, &linebuf);
}

void log_signal_m(int logfd, loglevel_t level, struct signalfd_siginfo *si) {
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    _log_signal(&linebuf, level, si, 1);

    _write_linebuf_fd(logfd, &linebuf);
}

void log_signal(loglevel_t level, struct signalfd_siginfo *si) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;
    
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;

    _log_signal(&linebuf, level, si, 0);

    _write_linebuf(logger, &linebuf);
}

const char *getstraddr(struct sockaddr *sa, socklen_t len, uint16_t *port) {
    static char ipaddr[TPX_IPV6_MAXLEN];
    ipaddr[0]='\0';
    
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        *port = ntohs(sin->sin_port);
        const char *ret = inet_ntop(AF_INET, &sin->sin_addr, ipaddr,
                                    sizeof(ipaddr));
        if (!ret)
            perror("inet_ntop");
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        *port = ntohs(sin6->sin6_port);
        const char *ret = inet_ntop(AF_INET6, &sin6->sin6_addr, ipaddr,
                                    sizeof(ipaddr));
        if (!ret)
            perror("inet_ntop");
    }
    return ipaddr;
}

void log_proxy(loglevel_t level, proxy_t *proxy, const char *subevent,
               const char *msg, const char *desc) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;
    
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;
    
    GUARD_APPEND(_base_schema(&linebuf, 0, level, PROXY_EVENT));

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " subevent", subevent,
                                    strlen(subevent)));

    uint16_t port = 0;
    static char portstr[12];
    if (proxy->client_addr.ss_family != AF_UNSPEC) {
        const char *client_ip = getstraddr((struct sockaddr *)&proxy->client_addr,
                                           proxy->client_addrlen, &port);
        snprintf(portstr, sizeof(portstr), "%hu", port);
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " client_ip",
                                        client_ip, strlen(client_ip)));
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " client_port",
                                        portstr, strlen(portstr)));
    }

    if (proxy->listener->listen_addr.ss_family != AF_UNSPEC) {
        const char *listen_ip =
            getstraddr((struct sockaddr *)&proxy->listener->listen_addr,
                       proxy->listener->listen_addrlen, &port);
        snprintf(portstr, sizeof(portstr), "%hu", port);
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " listen_ip",
                                        listen_ip, strlen(listen_ip)));
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " listen_port",
                                        portstr, strlen(portstr)));
    }

    if (proxy->listener->peer_addr.ss_family != AF_UNSPEC) {
        const char *server_ip =
            getstraddr((struct sockaddr *)&proxy->listener->peer_addr,
                       proxy->listener->peer_addrlen, &port);
        snprintf(portstr, sizeof(portstr), "%hu", port);
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " server_ip",
                                        server_ip, strlen(server_ip)));
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " server_port",
                                        portstr, strlen(portstr)));
    }

    if (msg) {
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " error_msg",
                                        msg, strlen(msg)));
    }
    if (desc) {
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " error_desc",
                                        desc, strlen(desc)));
    } else if (ERR_peek_error()) {
        GUARD_APPEND(_linebuf_append(&linebuf, " error_desc=\"",
                                     sizeof(" error_desc=\"")-1,
                                     TPX_MODE_NONE));
        GUARD_APPEND(_linebuf_append_ossl(&linebuf));
        GUARD_APPEND(_linebuf_putc(&linebuf, '"'));
    }
    
    _write_linebuf(logger, &linebuf);
}

void log_listener_listen(loglevel_t level, listen_t *listener) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;
    
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;
    const tpx_listen_conf_t *config = listener->config;
    
    GUARD_APPEND(_base_schema(&linebuf, 1, level, CONFIG_LOAD_EVENT));

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " target_ip",
                                    config->target_ip,
                                    strlen(config->target_ip)));

    char port[12];
    snprintf(port, sizeof(port), "%hu", config->target_port);
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " target_port",
                                    port, strlen(port)));

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " listen_ip",
                                    config->target_ip,
                                    strlen(config->target_ip)));

    snprintf(port, sizeof(port), "%hu", config->listen_port);
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " listen_port",
                                    port, strlen(port)));
    
    if (config->cert_chain) {
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " cert_chain",
                                        config->cert_chain,
                                        strlen(config->cert_chain)));
    } else {
        GUARD_APPEND(_linebuf_append(&linebuf, " cacerts=\"",
                                     sizeof(" cacerts=\"")-1,
                                     TPX_MODE_NONE));
        for (int i=0; i < config->cacerts_count; ++i) {
            GUARD_APPEND(_linebuf_append(&linebuf, config->cacerts[i],
                                         strlen(config->cacerts[i]),
                                         TPX_MODE_SANITIZE));
            if (i+1 < config->cacerts_count)
                GUARD_APPEND(_linebuf_putc(&linebuf, ':'));
        }
        GUARD_APPEND(_linebuf_putc(&linebuf, '"'));
        
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " servcert",
                                        config->servcert,
                                        strlen(config->servcert)));
    }

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " servkey",
                                    config->servkey,
                                    strlen(config->servkey)));

    _write_linebuf(logger, &linebuf);
}

void log_handshake(loglevel_t level, proxy_t *proxy, const char *outcome) {
    logger_t *logger = &g_shmem->logger;
    if (!logger->enabled || logger->loglevel < level)
        return;
    
    static linebuf_t linebuf;
    linebuf.u.len = LINEBUF_OFFSET;
    
    GUARD_APPEND(_base_schema(&linebuf, 0, level, HANDSHAKE_EVENT));

    GUARD_APPEND(_linebuf_append_kv(&linebuf, " subevent", "handshake",
                                    sizeof("handshake")-1));
    GUARD_APPEND(_linebuf_append_kv(&linebuf, " outcome", outcome,
                                    strlen(outcome)));

    uint16_t port = 0;
    static char portstr[12];
    if (proxy->client_addr.ss_family != AF_UNSPEC) {
        const char *client_ip = getstraddr((struct sockaddr *)&proxy->client_addr,
                                           proxy->client_addrlen, &port);
        snprintf(portstr, sizeof(portstr), "%hu", port);
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " client_ip",
                                        client_ip, strlen(client_ip)));
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " client_port",
                                        portstr, strlen(portstr)));
    }

    if (proxy->listener->listen_addr.ss_family != AF_UNSPEC) {
        const char *listen_ip =
            getstraddr((struct sockaddr *)&proxy->listener->listen_addr,
                       proxy->listener->listen_addrlen, &port);
        snprintf(portstr, sizeof(portstr), "%hu", port);
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " listen_ip",
                                        listen_ip, strlen(listen_ip)));
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " listen_port",
                                        portstr, strlen(portstr)));
    }

    
    if (strncmp(outcome, "denied", sizeof("denied"))==0 ||
        strncmp(outcome, "failed", sizeof("failed"))==0) {
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " error_msg",
                                        "Handshake failed",
                                        strlen("Handshake failed")));
    }

    if (strcmp(outcome, "failed")==0) {
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " error_desc",
                                        strerror(errno),
                                        strlen(strerror(errno))));
    } else if (strcmp(outcome, "denied")==0) {
        GUARD_APPEND(_linebuf_append(&linebuf, " error_desc=\"",
                                     sizeof(" error_desc=\"")-1,
                                     TPX_MODE_NONE));
        GUARD_APPEND(_linebuf_append_ossl(&linebuf));
        GUARD_APPEND(_linebuf_putc(&linebuf, '"'));
    }

    if (strcmp(outcome, "granted")==0) {
        assert(proxy->ssl);
        const SSL_CIPHER *cipher = SSL_get_current_cipher(proxy->ssl);
        const char *cipherstr = SSL_CIPHER_get_name(cipher);
        GUARD_APPEND(_linebuf_append_kv(&linebuf, " ciphersuite",
                                        cipherstr, strlen(cipherstr)));
    }
    
    _write_linebuf(logger, &linebuf);
}

/* Internal functions */
int _base_schema(linebuf_t *linebuf, int is_master, loglevel_t level,
                 const char *event) {
    static char metadata[128];
    size_t len = snprintf(metadata, sizeof(metadata),
                          "timestamp=%s service=%s process_type=%s pid=%s "
                          "level=%s event=%s",
                          _rfc3339_time(), "tlsproxy",
                          is_master ? "master" : "worker", _pid(),
                          strlevel(level), event);
    if (len >= sizeof(metadata))
        len = sizeof(metadata)-1;
    return _linebuf_append(linebuf, metadata, len, TPX_MODE_NONE);
}

int _linebuf_putc(linebuf_t *linebuf, const char c) {
    if (linebuf->u.len == TPX_LOG_LINE_MAX) return -1;
    
    linebuf->u.buf[linebuf->u.len++] = c;
    return 0;
}

int _linebuf_append(linebuf_t *linebuf, const char *str, size_t len,
                    int mode) {
    assert(linebuf->u.len < TPX_LOG_LINE_MAX);

    int (*transform)(const char, char **, const char*);
    if (mode == TPX_MODE_SANITIZE)
        transform = _sanitize_c;
    else if (mode == TPX_MODE_HEX)
        transform = _hex_c;

    if (mode != TPX_MODE_NONE) {
        char *sanitized = linebuf->u.buf;
        // endptrs point to the null terminator
        const char *str_endptr = str+len;
        const char *san_endptr = &sanitized[TPX_LOG_LINE_MAX];
        char *sanptr = &sanitized[linebuf->u.len];

        uint8_t filled = 0;
        for (const char *cursor = str; cursor < str_endptr; ++cursor) {
            if (transform(*cursor, &sanptr, san_endptr) == -1) {
                filled = 1;
                break;
            }
        }

        linebuf->u.len = sanptr - sanitized;
        if (filled) return -1;
    } else {
        memcpy(linebuf->u.buf + linebuf->u.len, str, len);
        linebuf->u.len += len;
    }

    assert(linebuf->u.len < TPX_LOG_LINE_MAX);
    return 0;
}

int _linebuf_append_ossl(linebuf_t *linebuf) {
    ERR_print_errors_cb(_linebuf_append_cb, linebuf);
    return 0;
}

int _linebuf_append_kv(linebuf_t *linebuf, const char *key,
                       const char *value, size_t value_len) {
    assert(linebuf->u.len < TPX_LOG_LINE_MAX);

    GUARD_APPEND_(_linebuf_append(linebuf, key, strlen(key), TPX_MODE_NONE));

    // If this errors the next will too
    GUARD_APPEND_(_linebuf_putc(linebuf, '='));
    GUARD_APPEND_(_linebuf_putc(linebuf, '"'));
    GUARD_APPEND_(_linebuf_append(linebuf, value, value_len,
                      TPX_MODE_SANITIZE));
    GUARD_APPEND_(_linebuf_putc(linebuf, '"'));

    assert(linebuf->u.len < TPX_LOG_LINE_MAX);
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

const char *strlevel(loglevel_t level) {
    static char levels[5][6] = {"FATAL", "ERROR", "WARN", "INFO", "DEBUG"};
    return levels[level];
}

void _write_linebuf_fd(int logfd, linebuf_t *linebuf) {
    linebuf->u.buf[linebuf->u.len++] = '\n';

    ssize_t retcode = write(logfd, &linebuf->u.buf[LINEBUF_OFFSET],
                            linebuf->u.len - LINEBUF_OFFSET);
    if (retcode == -1)
        perror("Writing log failed");
}

int _linebuf_append_cb(const char *str, size_t len, void *u) {
    return _linebuf_append((linebuf_t *)u, str, len, TPX_MODE_SANITIZE);
}

void _write_linebuf(logger_t *logger, linebuf_t *line) {
    line->u.buf[line->u.len++] = '\n';
    
    if (pthread_mutex_lock(&logger->write_lock)) {
        perror("pthread_mutex_lock when logging");
        return;
    }
    
    if (!_ringbuf_fits(logger, line->u.len)) {
        fprintf(stderr, "Ring buffer full, dropping new logs...\n");
        return;
    }
    
    uint32_t w_idx = logger->write_idx;
    
    if (w_idx + line->u.len > TPX_LOGBUF_SIZE) {
        // Wrap the message around the ring buffer
        memcpy(&logger->log_buf[w_idx],
               line->u.buf, TPX_LOGBUF_SIZE - w_idx);
        memcpy(&logger->log_buf[0],
               &line->u.buf[TPX_LOGBUF_SIZE - w_idx],
               line->u.len - (TPX_LOGBUF_SIZE - w_idx));
        w_idx = line->u.len - (TPX_LOGBUF_SIZE-w_idx);
    } else {
        memcpy(&logger->log_buf[w_idx], line->u.buf, line->u.len);
        w_idx += line->u.len;
        if (w_idx == TPX_LOGBUF_SIZE)
            w_idx = 0;
    }

    logger->log_buf[w_idx] = '\0';
    INC_WRAP(w_idx);
    
    logger->write_idx = w_idx;
    pthread_mutex_unlock(&logger->write_lock);
    
    // Notify the parent process that we're ready to go
    uint64_t count=1;
    write(logger->eventfd, &count, sizeof(count));
}

void _log_system_err(linebuf_t *linebuf, loglevel_t level,
                     const char *msg, int errtype,
                     int is_master) {
    GUARD_APPEND(_base_schema(linebuf, is_master, level, ERR_EVENT));

    GUARD_APPEND(_linebuf_append_kv(linebuf, " error_msg", msg,
                                    strlen(msg)));

    switch (errtype) {
    case TPX_ERR_PLAIN:
        break;
    case TPX_ERR_ERRNO:
        GUARD_APPEND(_linebuf_append_kv(linebuf, " error_desc", strerror(errno),
                                        strlen(strerror(errno))));
        break;
    case TPX_ERR_OSSL:
        GUARD_APPEND(_linebuf_append(linebuf, " error_desc=\"",
                                     sizeof(" error_desc=\"")-1,
                                     TPX_MODE_NONE));
        GUARD_APPEND(_linebuf_append_ossl(linebuf));
        GUARD_APPEND(_linebuf_putc(linebuf, '"'));
        break;
    }
}


void _log_signal(linebuf_t *linebuf, loglevel_t level,
                 struct signalfd_siginfo *si, int is_master) {
    GUARD_APPEND(_base_schema(linebuf, is_master, level, SIGNAL_EVENT));

    static char signum[6];
    snprintf(signum, sizeof(signum), "%d", si->ssi_signo);
    GUARD_APPEND(_linebuf_append_kv(linebuf, " signal_num", signum,
                                    strlen(signum)));

    const char *sstr = strsignal(si->ssi_signo);
    GUARD_APPEND(_linebuf_append_kv(linebuf, " signal_string",
                                    sstr, strlen(sstr)));

    static char pid[12];
    snprintf(pid, sizeof(pid), "%d", si->ssi_pid);
    GUARD_APPEND(_linebuf_append_kv(linebuf, " recvd_from",
                                    pid, strlen(pid)));
}

// Sanitize characters one by one, but stop if we reach endptr
int _sanitize_c(const char c, char **outptr, const char *endptr) {
    // Output at most 2 characters per input character
    if (*outptr + 1 >= endptr) return -1;

    // I had to force myself not to use *(*outptr)++ for this
    if (isprint(c)) {
        **outptr = c;
        *outptr += 1;
    } else {
        switch (c) {
        case '\n':
            **outptr = '\\';
            *outptr += 1;
            **outptr = 'n';
            *outptr += 1;
            break;
        case '\\':
            **outptr = '\\';
            *outptr += 1;
            **outptr = '\\';
            *outptr += 1;
            break;
        case '\r':
            **outptr = '\\';
            *outptr += 1;
            **outptr = 'r';
            *outptr += 1;
            break;
        case '"':
            **outptr = '\\';
            *outptr += 1;
            **outptr = '"';
            *outptr += 1;
            break;
        default:
            // If we want to use snprintf we need space for the null byte too
            if (*outptr + 4 >= endptr) return -1;
            snprintf(*outptr, 5, "\\x%02x", (const unsigned char)c);
            *outptr += 4;
            break;
        }
    }
    return 0;
}

int _hex_c(const char c, char **outptr, const char *endptr) {
    // Output at most 2 characters per input character
    if (*outptr + 2 >= endptr) return -1;
    snprintf(*outptr, 3, "%02x", (const unsigned char)c);
    *outptr += 2;
    return 0;
}

int _ringbuf_fits(logger_t *logger, uint32_t len) {
    return(((TPX_LOGBUF_SIZE + logger->read_idx - logger->write_idx - 1)
           % TPX_LOGBUF_SIZE) >= len);
}
