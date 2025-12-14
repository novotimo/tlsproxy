#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "config.h"
#include "errors.h"
#include "event.h"
#include "listen.h"
#include "logging.h"
#include "ngx_rbtree.h"
#include "proxy.h"
#include "shmem.h"
#include "timeutils.h"


#define TPX_MAX_EVENTS 100 /**< @brief The maximum number of events in epoll */
#define TPX_NARGS 2 /**< @brief The number of arguments to this program */
#define TPX_ARG_CONFFILE 1 /**< @brief The config file argument */

#define NAME closed /**< @brief The name of the hash set */
#define KEY_TY uint64_t /**< @brief The key type of the hash set */
#define HASH_FN vt_hash_integer /**< @brief The hash function */
#define CMPR_FN vt_cmpr_integer /**< @brief The compare function */
#include "verstable.h"


void usage(const char *prog);
void child_loop(tpx_config_t *tpx_config, SSL_CTX *ssl_ctx, int efd);
void parent_loop(tpx_config_t *tpx_config, pid_t *pids,
                 int logfd, int sigfd, int efd);
tpx_config_t *load_config(const char *conf_file);
void start_listeners(tpx_config_t *config, int epollfd);
static inline uint64_t del_tag(void *ptr);

void block_signals(sigset_t *mask, int logfd);
void init_shmem(tpx_config_t *config);
int init_logger(tpx_config_t *config);

SSL_CTX *init_openssl(tpx_config_t *config, int logfd);
void load_servcert(tpx_config_t *config, SSL_CTX *ctx, int logfd);
void load_cacerts(tpx_config_t *config, SSL_CTX *ctx, int logfd);
void load_servkey(tpx_config_t *config, SSL_CTX *ctx, int logfd);

void _fatal(int logfd, const char *msg, int errtype);
void _child_fatal(const char *msg, int errtype);


static const cyaml_config_t cyaml_config = {
    .log_fn = cyaml_log,
    .mem_fn = cyaml_mem,
    .log_level = CYAML_LOG_WARNING,
};

/** @brief Delete the 2-bit tag from a tagged pointer */
static inline uint64_t del_tag(void *ptr) {
    return (uint64_t)ptr & ~(uint64_t)0x3;
}


/** @brief Get usage and exit */
void usage(const char *pname) {
    fprintf(stderr, "Usage: %s <config.yml>\n", pname);
    exit(EXIT_FAILURE);
}

void _fatal(int logfd, const char *msg, int errtype) {
    log_system_err_m(logfd, LL_FATAL, msg, errtype);
    // TODO: graceful shutdown
    errx(EXIT_FAILURE, "%s", msg);
}

void _child_fatal(const char *msg, int errtype) {
    log_system_err(LL_FATAL, msg, errtype);
    // TODO: graceful shutdown
    errx(EXIT_FAILURE, "%s", msg);
}

void init_shmem(tpx_config_t *config) {
    g_shmem = mmap(NULL, sizeof(shared_t), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shmem == MAP_FAILED)
        err(EXIT_FAILURE, "mmap shared memory");
}

int init_logger(tpx_config_t *config) {
    if (!config->logfile) {
        printf("Disabling logging\n");
        return -1;
    }
    int logfd = open(config->logfile,
                     O_APPEND | O_CREAT | O_WRONLY,
                     S_IRUSR | S_IWUSR);
    if (logfd == -1)
        err(EXIT_FAILURE, "open log file '%s'", config->logfile);
    g_shmem->logger.enabled = 1;
    if (config->loglevel)
        g_shmem->logger.loglevel = *config->loglevel;
    else
        g_shmem->logger.loglevel = LL_INFO;
    
    pthread_mutexattr_t attrs;
    pthread_mutexattr_init(&attrs);
    pthread_mutexattr_setpshared(&attrs, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&g_shmem->logger.write_lock, &attrs);
    printf("Logging initialized\n");
    return logfd;
}

void block_signals(sigset_t *mask, int logfd) {
    sigemptyset(mask);
    sigaddset(mask, SIGKILL);
    sigaddset(mask, SIGTERM);
    sigaddset(mask, SIGINT);
    sigaddset(mask, SIGHUP);
    sigaddset(mask, SIGQUIT);
    sigaddset(mask, SIGPIPE);
    sigaddset(mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, mask, NULL) == -1)
        _fatal(logfd, "sigprocmask failed blocking signals", TPX_ERR_ERRNO);
}

/** @brief Inits OpenSSL and epoll then passes to main loop */
int main(int argc, char *argv[]) {
    printf("TLS Proxy starting\n");
    
    if (argc != TPX_NARGS)   
        usage(argv[0]);

    tpx_config_t *tpx_config = load_config(argv[TPX_ARG_CONFFILE]);

    // Init logging ASAP
    init_shmem(tpx_config);
    int logfd = init_logger(tpx_config);
    log_startup(logfd, LL_INFO, argc, argv);
    log_config_load(logfd, LL_INFO, tpx_config);
    
    // This can possibly overwrite environ a bit, but we don't use it anyway
    for (int i=0; i<argc; ++i)
        memset(argv[i], 0, strlen(argv[i]));
    sprintf(argv[0], "tlsproxy: master");
    
    /* I hate SIGPIPE! */
    sigset_t mask;
    block_signals(&mask, logfd);
    
    // This has to be done here so we don't need to pass the mask to parent_loop
    int sfd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (sfd == -1)
        _fatal(logfd, "Couldn't make signalfd", TPX_ERR_ERRNO);
    
    // This has to be done here so workers can access it too
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (efd == -1)
        _fatal(logfd, "Couldn't make eventfd", TPX_ERR_ERRNO);
    
    g_shmem->logger.eventfd = efd;

    pid_t *pids = calloc(tpx_config->nworkers, sizeof(pid_t));
    if (!pids)
        _fatal(logfd, "Couldn't allocate PID list", TPX_ERR_ERRNO);
    
    // Try with this outside for now
    SSL_CTX *ssl_ctx = init_openssl(tpx_config, logfd);
    for (int i=0; i<tpx_config->nworkers; ++i) {
        pid_t pid = fork();
        switch (pid) {
        case -1:
            _fatal(logfd, "Couldn't fork worker process", TPX_ERR_ERRNO);
        case 0:
            free(pids);
            sprintf(argv[0], "tlsproxy: worker");
            child_loop(tpx_config, ssl_ctx, efd);
            exit(EXIT_SUCCESS);
        default:
            pids[i] = pid;
            log_worker(logfd, LL_INFO, TPX_WORKER_ALIVE, i, pid);
        }
    }
    parent_loop(tpx_config, pids, logfd, sfd, efd);

    return(EXIT_SUCCESS);
}

void parent_loop(tpx_config_t *config,
                 pid_t *pids,
                 int logfd,
                 int sigfd,
                 int efd) {
    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        _fatal(logfd, "Couldn't create epoll fd", TPX_ERR_ERRNO);
    struct epoll_event events[TPX_MAX_EVENTS];

    struct epoll_event ev;
    // Add eventfd
    ev.events = EPOLLIN;
    ev.data.fd = efd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, efd, &ev) == -1) {
        for (int i=0; i<config->nworkers; ++i)
            kill(pids[i], SIGKILL);
        _fatal(logfd, "Couldn't add eventfd to epoll", TPX_ERR_ERRNO);
    }
    // Add signalfd
    ev.events = EPOLLIN;
    ev.data.fd = sigfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &ev) == -1) {
        for (int i=0; i<config->nworkers; ++i)
            kill(pids[i], SIGKILL);
        _fatal(logfd, "Couldn't add signalfd to epoll", TPX_ERR_ERRNO);
    }

    for (;;) {
        int nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);
        for (size_t n=0; n<nfds; ++n) {
            if (events[n].data.fd == efd) {
                uint64_t count = 0;
                if (read(efd, &count, sizeof(count)) < 0) {
                    log_system_err_m(logfd, LL_WARN, "Error reading eventfd",
                                     TPX_ERR_ERRNO);
                    continue;
                }
                write_logs(logfd, &g_shmem->logger, count);
            } else if (events[n].data.fd == sigfd) {
                struct signalfd_siginfo si;
                read(sigfd, &si, sizeof(si));
                log_signal_m(logfd, LL_WARN, &si);

                int sig;
                if (si.ssi_signo == SIGCHLD)
                    sig = SIGKILL;
                else
                    sig = si.ssi_signo;

                for (int i=0; i<config->nworkers; ++i)
                    kill(pids[i], sig);
                exit(EXIT_SUCCESS);
            }
        }
    }
}

void child_loop(tpx_config_t *tpx_config, SSL_CTX *ssl_ctx, int efd) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGKILL);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGQUIT);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        _child_fatal("sigprocmask couldn't unblock signals", TPX_ERR_ERRNO);
    
    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        _child_fatal("Couldn't create epoll in worker", TPX_ERR_ERRNO);

    start_listeners(tpx_config, epollfd);

    struct epoll_event events[TPX_MAX_EVENTS];
    closed closed_set;
    closed_init(&closed_set);

    proxy_init_timeouts();
    
    for (;;) {
        // Get min timeout
        int notimeouts = 0;
        int next_timeout = -1;
        while (!notimeouts) {
            if (timeouts.root == timeouts.sentinel) {
                notimeouts = 1;
                break;
            }
            
            ngx_rbtree_node_t *timeout = ngx_rbtree_min(timeouts.root,
                                                        timeouts.sentinel);
            if (timeout_expired(timeout->key)) {
                proxy_t *proxy = ngx_rbtree_data(timeout, proxy_t, timer);
                // We get deleted from the rbtree in here
                proxy_handle_timeout(proxy, epollfd);
            } else {
                // timeout->key - gettime() >= 0 (from !timeout_expired),
                // and we don't create timeouts that are big enough to fill ints
                next_timeout = (int)(timeout->key - gettime());
                notimeouts = 1;
            }
        }
        
        int nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, next_timeout);
        for (size_t n=0; n < nfds; ++n) {
            closed_itr it = closed_get(&closed_set,
                                       del_tag(events[n].data.ptr));
            if (!closed_is_end(it))
                continue;
            
            tpx_err_t ev_ret = dispatch_events(events[n].data.ptr, epollfd,
                                               events[n].events, ssl_ctx,
                                               tpx_config->connect_timeout);
            if (ev_ret == TPX_CLOSED) {
                it = closed_insert(&closed_set, del_tag(events[n].data.ptr));
                if (closed_is_end(it))
                    _child_fatal("child_loop: Ran out of memory for hash table",
                                 TPX_ERR_PLAIN);
            }
        }
        closed_clear(&closed_set);
    }
}

/** @brief Loads and validates the config file */
tpx_config_t *load_config(const char *config_file) {
    tpx_config_t *tpx_config;
    cyaml_err_t conf_err = cyaml_load_file(config_file,
                                           &cyaml_config,
                                           &top_schema,
                                           (cyaml_data_t **)&tpx_config, NULL);
    if (conf_err != CYAML_OK) {
        errx(EXIT_FAILURE, "Config error: %s", cyaml_strerror(conf_err));
    } else if (tpx_validate_conf(tpx_config) != TPX_SUCCESS) {
        errx(EXIT_FAILURE, "Config file '%s' failed verification", config_file);
    }
    
    return tpx_config;
}

/** @brief Start the listener sockets (only one for now) */
void start_listeners(tpx_config_t *tpx_config, int epollfd) {
    listen_t *listener = create_listener(tpx_config->listen_ip,
                                         tpx_config->listen_port,
                                         tpx_config->target_ip,
                                         tpx_config->target_port);
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = listener;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->fd, &ev) == -1)
        _child_fatal("Couldn't add listen socket to epoll", TPX_ERR_ERRNO);
}

/** @brief Inits SSL_CTX for use as a TLS server, loading certs */
SSL_CTX *init_openssl(tpx_config_t *config, int logfd) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        _fatal(logfd, "Couldn't create OpenSSL context", TPX_ERR_OSSL);

    // TODO: make the ciphersuites and accepted TLS versions configurable
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Couldn't set minimum TLS protocol version", TPX_ERR_OSSL);
    }

    int opts =
        SSL_OP_IGNORE_UNEXPECTED_EOF
        | SSL_OP_NO_RENEGOTIATION
        | SSL_OP_CIPHER_SERVER_PREFERENCE;
    
    SSL_CTX_set_options(ctx, opts);

    if (config->cacerts != NULL) {
        load_servcert(config, ctx, logfd);
        load_cacerts(config, ctx, logfd);
    } else if (config->cert_chain != NULL) {
        if (SSL_CTX_use_certificate_chain_file(ctx, config->cert_chain) != 1) {
            SSL_CTX_free(ctx);
            _fatal(logfd, "Couldn't load cert chain", TPX_ERR_OSSL);
        }

        STACK_OF(X509) *certs;
        SSL_CTX_get0_chain_certs(ctx, &certs);
        for (int i=0; i<sk_X509_num(certs); ++i)
            log_cert_load(logfd, LL_INFO, sk_X509_value(certs, i), 0);
    } else {
        _fatal(logfd, "Config contains both cert-chain and cacerts",
               TPX_ERR_PLAIN);
    }

    int flags = config->cacerts == NULL
                    ? SSL_BUILD_CHAIN_FLAG_UNTRUSTED |
                      SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR
                    : 0;

    if (SSL_CTX_build_cert_chain(ctx, flags) != 1) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to build cert chain", TPX_ERR_OSSL);
    }

    load_servkey(config, ctx, logfd);

    // No mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

/** @brief Load the server certificate into the SSL_CTX */
void load_servcert(tpx_config_t *config, SSL_CTX *ctx, int logfd) {
    BIO *leaf_bio = BIO_new_file(config->servcert, "r");
    X509 *leaf = NULL;
    if (!PEM_read_bio_X509(leaf_bio, &leaf, NULL, NULL)) {
        BIO_free(leaf_bio);
        _fatal(logfd, "Failed to load server cert", TPX_ERR_OSSL);
    }
    BIO_free(leaf_bio);
    log_cert_load(logfd, LL_INFO, leaf, 0);
        
    if (SSL_CTX_use_certificate(ctx, leaf) != 1) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to add server certificate to CTX", TPX_ERR_OSSL);
    }
}

/** @brief Load the CA certificates into the SSL_CTX */
void load_cacerts(tpx_config_t *config, SSL_CTX *ctx, int logfd) {
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    for (int i=0; i<config->cacerts_count; ++i) {
        if (!X509_LOOKUP_load_file(lookup, config->cacerts[i],
                                   X509_FILETYPE_PEM))
            _fatal(logfd, "Couldn't load CA certificate", TPX_ERR_OSSL);
    }

    SSL_CTX_set_cert_store(ctx, store);
    
    STACK_OF(X509) *certs;
    SSL_CTX_get0_chain_certs(ctx, &certs);
    for (int i=0; i<sk_X509_num(certs); ++i)
        log_cert_load(logfd, LL_INFO, sk_X509_value(certs, i), 0);
}

/** @brief Load the server private key into the SSL_CTX */
void load_servkey(tpx_config_t *config, SSL_CTX *ctx, int logfd) {
    BIO *pkey_bio = BIO_new_file(config->servkey, "r");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pkey_bio, NULL, NULL,
                                             (void *)config->servkeypass);
    BIO_free(pkey_bio);
    if (pkey == NULL) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to read server key", TPX_ERR_OSSL);
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to load server key into ctx", TPX_ERR_OSSL);
    }
}
