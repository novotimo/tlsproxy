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
#include <sys/wait.h>
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
void child_loop(tpx_config_t *tpx_config, SSL_CTX **ssl_ctxs, int efd,
                int sigfd);
void parent_loop(tpx_config_t **tpx_config, pid_t **pids,
                 int *logfd, int sigfd, int efd);
tpx_config_t *load_config(const char *conf_file);
listen_t **start_listeners(tpx_config_t *config, int epollfd, size_t *ret_len,
                           SSL_CTX **ssl_ctxs);
void close_listeners(int epollfd, listen_t **listeners, size_t len);
void free_listeners(listen_t **listeners, size_t len);
static inline uint64_t del_tag(void *ptr);

void block_signals(sigset_t *mask, int logfd);
void init_shmem(tpx_config_t *config);
int init_logger(tpx_config_t *config);

SSL_CTX *init_openssl(const tpx_listen_conf_t *config, int logfd);
int load_servcert(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd);
int load_cacerts(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd);
int load_servkey(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd);

int handle_reload(tpx_config_t **config, int *logfd, pid_t **pids);

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

char *config_fname = NULL;
// Crikey! I'm parameterizing my functions with a global!
// This is a parameter of _fatal and _child_fatal and is here so that
// we can easily reuse startup functions during reload in a way that
// doesn't shut down the whole program.
// Simon Peyton Jones, I'm sorry I did this.
uint8_t in_startup = 1;
uint8_t respawn = 0;
uint8_t in_shutdown = 0;
int left_to_close = 0;
extern uint32_t nproxies;


/** @brief Get usage and exit */
void usage(const char *pname) {
    fprintf(stderr, "Usage: %s <config.yml>\n", pname);
    exit(EXIT_FAILURE);
}

void _fatal(int logfd, const char *msg, int errtype) {
    log_system_err_m(logfd, LL_FATAL, msg, errtype);
    if (in_startup)
        errx(EXIT_FAILURE, "%s", msg);
}

void _child_fatal(const char *msg, int errtype) {
    log_system_err(LL_FATAL, msg, errtype);
    if (in_startup)
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
        return -1;
    }
    int logfd = open(config->logfile,
                     O_APPEND | O_CREAT | O_WRONLY,
                     S_IRUSR | S_IWUSR);
    if (logfd == -1)
        return -2;
    g_shmem->logger.enabled = 1;
    if (config->loglevel)
        g_shmem->logger.loglevel = *config->loglevel;
    else
        g_shmem->logger.loglevel = LL_INFO;
    
    pthread_mutexattr_t attrs;
    pthread_mutexattr_init(&attrs);
    pthread_mutexattr_setpshared(&attrs, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&g_shmem->logger.write_lock, &attrs);
    pthread_mutexattr_destroy(&attrs);
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

    size_t cfilelen = strlen(argv[TPX_ARG_CONFFILE]);
    config_fname = malloc(cfilelen+1);
    strncpy(config_fname, argv[TPX_ARG_CONFFILE], cfilelen);
    config_fname[cfilelen] = '\0';
    tpx_config_t *tpx_config = load_config(argv[TPX_ARG_CONFFILE]);

    // Init logging ASAP
    init_shmem(tpx_config);
    int logfd = init_logger(tpx_config);
    if (logfd == -1)
        printf("Disabling logging\n");
    else if (logfd == -2)
        err(EXIT_FAILURE, "Couldn't load logfile '%s'", tpx_config->logfile);
    else
        printf("Logging initialized\n");

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
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
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

    // We need to save this here so that we can free the right amount
    // of SSL_CTXs after reload
    int nlisteners = tpx_config->listeners_count;
    SSL_CTX **ssl_ctxs;
    for (;;) {
        // When respawning:
        // - respawn is set to 1
        // - Pids are already there
        // - Dead pids are set to -1
        // - ssl_ctxs are already there
        if (!respawn) {
            ssl_ctxs = calloc(nlisteners, sizeof(SSL_CTX *));
            for (int i=0; i<nlisteners; ++i)
                ssl_ctxs[i] = init_openssl(&tpx_config->listeners[i], logfd);
        }
        respawn = 0;
        
        for (int i=0; i<tpx_config->nworkers; ++i) {
            // If this isn't the worker needing a respawn
            if (respawn && pids[i] != -1)
                continue;
            pid_t pid = fork();
            switch (pid) {
            case -1:
                _fatal(logfd, "Couldn't fork worker process", TPX_ERR_ERRNO);
            case 0:
                free(pids);
                sprintf(argv[0], "tlsproxy: worker");
                child_loop(tpx_config, ssl_ctxs, efd, sfd);
                exit(EXIT_SUCCESS);
            default:
                pids[i] = pid;
                log_worker(logfd, LL_WARN, TPX_WORKER_ALIVE, pid);
            }
        }
        parent_loop(&tpx_config, &pids, &logfd, sfd, efd);

        // From here on out the config could have been reloaded
        if (!respawn) {
            for (int i=0; i<nlisteners; ++i) {
                SSL_CTX_free(ssl_ctxs[i]);
            }
            free(ssl_ctxs);
            nlisteners = tpx_config->listeners_count;
        }
    }

    return(EXIT_SUCCESS);
}

void parent_loop(tpx_config_t **config_,
                 pid_t **pids_,
                 int *logfd_,
                 int sigfd,
                 int efd) {
    // We have pointers to the first three because these are altered
    // on reload
    tpx_config_t *config = *config_;
    pid_t *pids = *pids_;
    int logfd = *logfd_;
    
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

    in_startup = 0;
    uint8_t finishing = 0;
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
                while (read(sigfd, &si, sizeof(si)) == sizeof(si)) {
                    log_signal_m(logfd, LL_INFO, &si);

                    int sig;
                    if (si.ssi_signo == SIGCHLD) {
                        // Don't want to leave any zombies
                        pid_t pid = -1;
                        int wstatus = 0;
                        while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
                            log_worker(logfd, LL_WARN, 0, pid /*, WEXITSTATUS(wstatus) */);

                            if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 77) {
                                for (int i=0; i<config->nworkers; ++i)
                                    kill(pids[i], SIGKILL);
                                exit(77);
                            }
                            
                            int found=0;
                            for (int i=0; i<config->nworkers; ++i) {
                                if (pids[i] == pid) {
                                    if (in_shutdown)
                                        --left_to_close;
                    
                                    respawn = 1;
                                    pids[i] = 0;
                                    finishing = 1;
                                    found = 1;
                                    break;
                                }
                            }
                        }
                        
                        continue;
                    } else if (si.ssi_signo == SIGHUP) {
                        if (handle_reload(config_, logfd_, pids_) == 1) {
                            finishing = 1;
                            continue;
                        }
                    } else if (si.ssi_signo == SIGPIPE) {
                        // All my homies hate SIGPIPE
                        continue;
                    }
                
                    in_shutdown = 1;
                    left_to_close = config->nworkers;
                    for (int i=0; i<left_to_close; ++i)
                        kill(pids[i], SIGHUP);
                }
            }
        }
        
        if (in_shutdown && left_to_close == 0)
            exit(EXIT_SUCCESS);

        if (finishing)
            goto cleanup;
    }

cleanup:
    close(epollfd);
}

void child_loop(tpx_config_t *tpx_config, SSL_CTX **ssl_ctxs, int efd,
                int sigfd) {
    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        _child_fatal("Couldn't create epoll in worker", TPX_ERR_ERRNO);

    size_t nlisteners;
    listen_t **listeners = start_listeners(tpx_config, epollfd, &nlisteners,
                                           ssl_ctxs);

    struct epoll_event ev, events[TPX_MAX_EVENTS];

    // Add signalfd
    ev.events = EPOLLIN;
    ev.data.fd = sigfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &ev) == -1)
        _child_fatal("Couldn't add signalfd to epoll", TPX_ERR_ERRNO);

    closed closed_set;
    closed_init(&closed_set);

    proxy_init_timeouts();

    in_startup = 0;
    
    for (;;) {
        if (in_shutdown && nproxies == 0) {
            for (int i=0; i<tpx_config->listeners_count; ++i)
                SSL_CTX_free(ssl_ctxs[i]);
            free(ssl_ctxs);
            
            close(epollfd);
            close(sigfd);
            closed_cleanup(&closed_set);
            free_listeners(listeners, nlisteners);
            exit(EXIT_SUCCESS);
        }
        
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
            if (events[n].data.fd == sigfd) {
                struct signalfd_siginfo si;
                read(sigfd, &si, sizeof(si));
                log_signal(LL_INFO, &si);

                int sig;
                if (si.ssi_signo == SIGHUP) {
                    close_listeners(epollfd, listeners, nlisteners);
                    in_shutdown = 1;
                } else if (si.ssi_signo == SIGPIPE) {
                    // All my homies hate SIGPIPE
                    continue;
                } else {
                    exit(EXIT_SUCCESS);
                }
                continue;
            }
            closed_itr it = closed_get(&closed_set,
                                       del_tag(events[n].data.ptr));
            if (!closed_is_end(it))
                continue;
            
            tpx_err_t ev_ret = dispatch_events(events[n].data.ptr, epollfd,
                                               events[n].events);
            if (ev_ret == TPX_CLOSED) {
                it = closed_insert(&closed_set, del_tag(events[n].data.ptr));
                if (closed_is_end(it))
                    log_system_err(LL_WARN, "Ran out of memory for closed fds",
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
        return NULL;
    } else if (tpx_validate_conf(tpx_config) != TPX_SUCCESS) {
        errx(EXIT_FAILURE, "Config file '%s' failed verification", config_file);
    }
    
    return tpx_config;
}

/** @brief Start the listener sockets (only one for now) */
listen_t **start_listeners(tpx_config_t *tpx_config, int epollfd, size_t *len,
                           SSL_CTX **ssl_ctxs) {
    *len = tpx_config->listeners_count;
    listen_t **listeners = calloc(*len, sizeof(listen_t *));
    for (int i=0; i < *len; ++i) {
        const tpx_listen_conf_t *lconf = &tpx_config->listeners[i];
        listeners[i] = create_listener(lconf, ssl_ctxs[i]);
        
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = listeners[i];
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listeners[i]->fd, &ev) == -1)
            _child_fatal("Couldn't add listen socket to epoll", TPX_ERR_ERRNO);
    }
    
    return listeners;
}

void close_listeners(int epollfd, listen_t **listeners, size_t len) {
    for (int i=0; i<len; ++i) {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, listeners[i]->fd, NULL);
        close(listeners[i]->fd);
    }
}

void free_listeners(listen_t **listeners, size_t len) {
    for (int i=0; i<len; ++i)
        free(listeners[i]);
}

/** @brief Inits SSL_CTX for use as a TLS server, loading certs */
SSL_CTX *init_openssl(const tpx_listen_conf_t *config, int logfd) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        _fatal(logfd, "Couldn't create OpenSSL context", TPX_ERR_OSSL);
        return NULL;
    }

    // TODO: make the ciphersuites and accepted TLS versions configurable
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Couldn't set minimum TLS protocol version", TPX_ERR_OSSL);
        return NULL;
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
            return NULL;
        }

        STACK_OF(X509) *certs;
        SSL_CTX_get0_chain_certs(ctx, &certs);
        for (int i=0; i<sk_X509_num(certs); ++i)
            log_cert_load(logfd, LL_INFO, sk_X509_value(certs, i), 0);
    } else {
        _fatal(logfd, "Config contains both cert-chain and cacerts",
               TPX_ERR_PLAIN);
        return NULL;
    }

    int flags = config->cacerts == NULL
                    ? SSL_BUILD_CHAIN_FLAG_UNTRUSTED |
                      SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR
                    : 0;

    if (SSL_CTX_build_cert_chain(ctx, flags) != 1) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to build cert chain", TPX_ERR_OSSL);
        return NULL;
    }

    load_servkey(config, ctx, logfd);

    // No mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

/** @brief Load the server certificate into the SSL_CTX */
int load_servcert(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd) {
    BIO *leaf_bio = BIO_new_file(config->servcert, "r");
    X509 *leaf = NULL;
    if (!PEM_read_bio_X509(leaf_bio, &leaf, NULL, NULL)) {
        BIO_free(leaf_bio);
        _fatal(logfd, "Failed to load server cert", TPX_ERR_OSSL);
        return 1;
    }
    BIO_free(leaf_bio);
    log_cert_load(logfd, LL_INFO, leaf, 0);

    if (SSL_CTX_use_certificate(ctx, leaf) != 1) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to add server certificate to CTX", TPX_ERR_OSSL);
        return 0;
    }
    return 1;
}

/** @brief Load the CA certificates into the SSL_CTX */
int load_cacerts(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd) {
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    for (int i=0; i<config->cacerts_count; ++i) {
        if (!X509_LOOKUP_load_file(lookup, config->cacerts[i],
                                   X509_FILETYPE_PEM)) {
            _fatal(logfd, "Couldn't load CA certificate", TPX_ERR_OSSL);
            return 0;
        }
    }

    SSL_CTX_set_cert_store(ctx, store);
    
    STACK_OF(X509) *certs;
    SSL_CTX_get0_chain_certs(ctx, &certs);
    for (int i=0; i<sk_X509_num(certs); ++i)
        log_cert_load(logfd, LL_INFO, sk_X509_value(certs, i), 0);
    return 1;
}

/** @brief Load the server private key into the SSL_CTX */
int load_servkey(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd) {
    BIO *pkey_bio = BIO_new_file(config->servkey, "r");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pkey_bio, NULL, NULL,
                                             (void *)config->servkeypass);
    BIO_free(pkey_bio);
    if (pkey == NULL) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to read server key", TPX_ERR_OSSL);
        return 0;
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        SSL_CTX_free(ctx);
        _fatal(logfd, "Failed to load server key into ctx", TPX_ERR_OSSL);
        return 0;
    }
    return 1;
}

int handle_reload(tpx_config_t **config, int *logfd, pid_t **pids) {
    assert(config_fname);
    tpx_config_t *new_config;
    cyaml_err_t conf_err = cyaml_load_file(config_fname, &cyaml_config,
                                           &top_schema,
                                           (cyaml_data_t **)&new_config, NULL);
    if (conf_err != CYAML_OK) {
        log_system_err_m_ex(*logfd, LL_ERROR, "Couldn't reload config",
                            cyaml_strerror(conf_err));
        return 0;
    }

    // This could be done better, I imagine. Make sure to watch config.c for
    // changes to the logic in tpx_validate_conf
    for (int i=0; i<new_config->listeners_count; ++i) {
        const tpx_listen_conf_t *listen_conf = &new_config->listeners[i];
        if (!listen_conf->cert_chain && !listen_conf->cacerts) {
            log_system_err_m_ex(
                *logfd, LL_ERROR, "Couldn't reload config",
                "Either 'cert-chain' or 'cacerts' must be provided");
            goto cleanup_conf;
        } else if (listen_conf->cert_chain &&
                   (listen_conf->cacerts || listen_conf->servcert)) {
            log_system_err_m_ex(*logfd, LL_ERROR, "Couldn't reload config",
                                "'cert-chain' can't be used together with 'cacerts'"
                                " or 'servcert'");
            goto cleanup_conf;
        } else if (listen_conf->cacerts && !listen_conf->servcert) {
            log_system_err_m_ex(*logfd, LL_ERROR, "Couldn't reload config",
                                "'servcert' must be specified if 'cacerts' is"
                );
            goto cleanup_conf;
        } else if (listen_conf->listen_port > UINT16_MAX) {
            log_system_err_m_ex(*logfd, LL_ERROR, "Couldn't reload config",
                                "'listen-port' must be a valid port");
            goto cleanup_conf;
        } else if (listen_conf->target_port > UINT16_MAX) {
            log_system_err_m_ex(*logfd, LL_ERROR, "Couldn't reload config",
                                "'target-port' must be a valid port");
            goto cleanup_conf;
        }
    }

    uint8_t old_enabled = g_shmem->logger.enabled;
    uint8_t old_loglevel = g_shmem->logger.loglevel;
    int new_logfd = init_logger(new_config);
    
    if (new_logfd == -2) {
        log_system_err_m(*logfd, LL_ERROR, "Couldn't update logfile",
                            TPX_ERR_ERRNO);
        goto restore_shmem;
    } else if (new_logfd == -1) {
        g_shmem->logger.enabled = 0;
    } else {
        g_shmem->logger.enabled = 1;
        if (new_config->loglevel)
            g_shmem->logger.loglevel = *new_config->loglevel;
        else
            g_shmem->logger.loglevel = LL_INFO;
    }


    for (int i=0; i<new_config->listeners_count; ++i) {
        // We don't actually use this context we've made, we just want to
        // prove that it will be made without errors
        SSL_CTX *ssl_ctx = init_openssl(&new_config->listeners[i], new_logfd);
        if (!ssl_ctx) {
            log_system_err_m(*logfd, LL_ERROR, "Couldn't reload config",
                             TPX_ERR_OSSL);
            goto restore_shmem;
        }
        SSL_CTX_free(ssl_ctx);
    }

    // Now we're fully convinced our new config is good
    int old_workers = (*config)->nworkers;
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t **)*config, 0);
    close(*logfd);

    *config = new_config;
    *logfd = new_logfd;

    pid_t *new_pids = calloc((*config)->nworkers, sizeof(pid_t));
    if (!new_pids) {
        perror("Couldn't allocate PID list");
        goto restore_shmem;
    }

    for (int i=0; i<old_workers; ++i)
        kill((*pids)[i], SIGHUP);
    left_to_close = old_workers;
    free(*pids);
    *pids = new_pids;

    return 1;

restore_shmem:
    g_shmem->logger.enabled = old_enabled;
    g_shmem->logger.loglevel = old_loglevel;
cleanup_conf:
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t **)&new_config, 0);
    return 0;
}
