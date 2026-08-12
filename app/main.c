#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
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
#include "version.h"


#define TPX_MAX_EVENTS 100 /**< @brief The maximum number of events in epoll */
#define TPX_NARGS_MIN 1
#define TPX_NARGS_MAX 2
#define TPX_ARG_CONFFILE 1 /**< @brief The config file argument */
#define TPX_CONFIG_DIR "/etc/tlsproxy"
#define TPX_DEFAULT_CONF "tlsproxy.yml"

#define TPX_VERSION_FLAG "-v"

#define TPX_RESTART_MAX 5 /**< @brief This many restarts per worker before we
                           * give up restarting them */
#define TPX_RESTART_WINDOW 10 /**< @brief If more than TPX_RESTART_MAX*nworkers
                               * restarts happen within this many seconds,
                               * shut down the program */

#define NAME closed /**< @brief The name of the hash set */
#define KEY_TY uint64_t /**< @brief The key type of the hash set */
#define HASH_FN vt_hash_integer /**< @brief The hash function */
#define CMPR_FN vt_cmpr_integer /**< @brief The compare function */
#include "verstable.h"


void usage(const char *prog);
void child_loop(tpx_config_t *tpx_config, SSL_CTX **ssl_ctxs,
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
tpx_err_t handle_signal(struct signalfd_siginfo *si,
                        tpx_config_t **config,
                        int *logfd,
                        pid_t **pids);
void init_shmem(void);
int init_logger(tpx_config_t *config);

SSL_CTX *init_openssl(const tpx_listen_conf_t *config, int logfd);
X509 *load_servcert(const tpx_listen_conf_t *config, int logfd);
STACK_OF(X509) *load_cacerts(const tpx_listen_conf_t *config, int logfd);
int load_chain_file(const tpx_listen_conf_t *config, int logfd,
                    STACK_OF(X509) **ca_certs, X509 **leaf);
int load_servkey(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd);
int build_chain(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd);

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
size_t left_to_close = 0;
extern uint32_t nproxies;

// We move environ's pointed-to block somewhere else to write argv[0] safely
extern char **environ;

static size_t   restarts = 0;
static uint64_t window_start = 0;


/** @brief Get usage and exit */
void usage(const char *pname) {
    fprintf(stderr, "Usage: %s [-v | <config.yml>]\n", pname);
    exit(EXIT_FAILURE);
}

/**
 * @brief Print fatal errors on startup, or during config reload
 *
 * If we're in startup, log a fatal error and terminate. If we're doing a
 * reload, we can't afford to terminate, so just print an error. This should
 * be run only on the master process.
 */
void _fatal(int logfd, const char *msg, int errtype) {
    if (in_startup) {
        log_system_err_m(logfd, LL_FATAL, msg, errtype);
        errx(EXIT_FAILURE, "%s", msg);
    } else {
        log_system_err_m(logfd, LL_ERROR, msg, errtype);
    }
}

void _child_fatal(const char *msg, int errtype) {
    log_system_err(LL_FATAL, msg, errtype);
    if (in_startup)
        errx(TPX_WORKER_FATAL, "%s", msg);
}

void save_environ(void) {
    for (char **cur = environ; *cur; ++cur)
        if ((*cur = strdup(*cur)) == NULL)
            err(EXIT_FAILURE, "duplicating environment string");
}

static inline void kill_safe(pid_t pid, int sig) {
    if (pid != -1) kill(pid, sig);
}

void init_shmem(void) {
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

    // This is initialized before `enabled` is set, since if this was
    // disabled before, between logger being enabled and the lock being
    // initialized, a worker could see `enabled == 1` and try to use the
    // uninitialized lock
    if (!g_shmem->logger.lock_initialized) {
        pthread_mutexattr_t attrs;
        pthread_mutexattr_init(&attrs);
        pthread_mutexattr_setpshared(&attrs, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&attrs, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(&g_shmem->logger.write_lock, &attrs);
        pthread_mutexattr_destroy(&attrs);

        g_shmem->logger.lock_initialized = 1;
    }

    g_shmem->logger.enabled = 1;
    if (config->loglevel)
        g_shmem->logger.loglevel = *config->loglevel;
    else
        g_shmem->logger.loglevel = LL_INFO;

    g_shmem->logger.droplines = 0;

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
    if (argc < TPX_NARGS_MIN || argc > TPX_NARGS_MAX)
        usage(argv[0]);

    if (argc == 1) {
        const char *conf_fname = TPX_CONFIG_DIR "/" TPX_DEFAULT_CONF;
        size_t cfilelen = sizeof(TPX_CONFIG_DIR "/" TPX_DEFAULT_CONF);
        config_fname = malloc(cfilelen);
        if (!config_fname)
            err(EXIT_FAILURE, "main: allocating configuration filename for default filename");
        strncpy(config_fname, conf_fname, cfilelen);
    } else {
        if (strcmp(argv[1], TPX_VERSION_FLAG) == 0) {
            printf("Version: %s\n", TLSPROXY_VERSION);
            exit(EXIT_SUCCESS);
        }

        size_t cfilelen = strlen(argv[TPX_ARG_CONFFILE]);
        config_fname = malloc(cfilelen+1);
        if (!config_fname)
            err(EXIT_FAILURE, "main: allocating configuration filename");

        strncpy(config_fname, argv[TPX_ARG_CONFFILE], cfilelen);
        config_fname[cfilelen] = '\0';
    }

    // Make stdout line buffered since we don't use stdout that much and
    // we don't want any messages to be duplicated after fork
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("TLS Proxy v%s starting\n", TLSPROXY_VERSION);

    tpx_config_t *tpx_config = load_config(config_fname);

    // Init logging ASAP
    init_shmem();
    int logfd = init_logger(tpx_config);
    if (logfd == -1)
        printf("Disabling logging\n");
    else if (logfd == -2)
        err(EXIT_FAILURE, "Couldn't load logfile '%s'", tpx_config->logfile);
    else
        printf("Logging initialized\n");

    log_startup(logfd, LL_INFO, argc, argv);
    log_config_load(logfd, LL_INFO, tpx_config);

    check_keyfiles(logfd, tpx_config);
    
    // This can possibly overwrite environ a bit, so let's save it
    char **envp;

    // Find the start of the last envvar
    for (envp = environ; *envp; ++envp);

    // Don't go before the start of environ
    if (envp != environ)
        --envp;

    // This is the whole block we're working with
    char *environ_end;
    if (*envp)
        environ_end = *envp + strlen(*envp);
    else
        environ_end = argv[argc-1] + strlen(argv[argc-1]);
    save_environ();

    // Now, we can just zero out the whole block of argv[0] to envp[last]
    // The assumption here is that that's a contiguous block
    size_t block_size = (size_t)(environ_end - argv[0]);
    memset(argv[0], 0, block_size);
    snprintf(argv[0], block_size, "tlsproxy: master");
    
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
    size_t nlisteners = tpx_config->listeners_count;
    SSL_CTX **ssl_ctxs = NULL;
    for (;;) {
        // When respawning:
        // - respawn is set to 1
        // - Pids are already there
        // - Dead pids are set to -1
        // - ssl_ctxs are already there
        if (!respawn) {
            ssl_ctxs = calloc(nlisteners, sizeof(SSL_CTX *));
            if (!ssl_ctxs)
                _fatal(logfd, "Couldn't allocate SSL contexts", TPX_ERR_ERRNO);

            for (size_t i=0; i<nlisteners; ++i)
                ssl_ctxs[i] = init_openssl(&tpx_config->listeners[i], logfd);
        }
        
        for (size_t i=0; i<tpx_config->nworkers; ++i) {
            // If this isn't the worker needing a respawn
            if (respawn && pids[i] != -1)
                continue;
            pid_t master_pid = getpid();
            pid_t pid = fork();
            switch (pid) {
            case -1:
                _fatal(logfd, "Couldn't fork worker process", TPX_ERR_ERRNO);
                exit(EXIT_FAILURE);
            case 0:
                free(pids);
                snprintf(argv[0], block_size, "tlsproxy: worker");

                // Make sure we die if the parent process does
                prctl(PR_SET_PDEATHSIG, SIGHUP);
                if (getppid() != master_pid)
                    exit(EXIT_FAILURE);

                child_loop(tpx_config, ssl_ctxs, sfd);
                exit(EXIT_SUCCESS);
            default:
                pids[i] = pid;
                log_worker(logfd, LL_WARN, TPX_WORKER_ALIVE, pid, -1);
            }
        }
        
        respawn = 0;
        parent_loop(&tpx_config, &pids, &logfd, sfd, efd);

        // From here on out the config could have been reloaded
        if (!respawn) {
            for (size_t i=0; i<nlisteners; ++i) {
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
        for (size_t i=0; i<config->nworkers; ++i)
            kill_safe(pids[i], SIGKILL);
        _fatal(logfd, "Couldn't add eventfd to epoll", TPX_ERR_ERRNO);
    }
    // Add signalfd
    ev.events = EPOLLIN;
    ev.data.fd = sigfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &ev) == -1) {
        for (size_t i=0; i<config->nworkers; ++i)
            kill_safe(pids[i], SIGKILL);
        _fatal(logfd, "Couldn't add signalfd to epoll", TPX_ERR_ERRNO);
    }

    in_startup = 0;
    uint8_t finishing = 0;
    for (;;) {
        int nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);

        if (nfds == -1) {
            if (errno == EINTR) {
                log_system_err_m(logfd, LL_WARN, "Waiting on epoll",
                                 TPX_ERR_ERRNO);
                continue;
            } else {
                log_system_err_m(logfd, LL_FATAL,
                                 "Couldn't wait on the epollfd", TPX_ERR_ERRNO);

                for (size_t i=0; i<config->nworkers; ++i)
                    kill_safe(pids[i], SIGHUP);

                exit(EXIT_FAILURE);
            }
        }
        for (size_t n=0; n<(size_t)nfds; ++n) {
            if (events[n].data.fd == efd) {
                uint64_t count = 0;
                if (read(efd, &count, sizeof(count)) < 0) {
                    log_system_err_m(logfd, LL_WARN, "Error reading eventfd",
                                     TPX_ERR_ERRNO);
                    continue;
                }

                count -= write_logs(logfd, &g_shmem->logger, count);

                // If we couldn't write all the logs, re-emit the events so we can try again
                if (count > 0 && write(efd, (void *)&count, sizeof(count)) != sizeof(count)) {
                    // This means we have a log desync, we can't really do anything but quit
                    err(EXIT_FAILURE, "Couldn't write log events to eventfd");
                }
            } else if (events[n].data.fd == sigfd) {
                struct signalfd_siginfo si;
                while (read(sigfd, &si, sizeof(si)) == sizeof(si)) {
                    if (handle_signal(&si, config_, logfd_, pids_)
                        == TPX_SUCCESS)
                        continue;
                    else
                        finishing = 1;
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

void child_loop(tpx_config_t *tpx_config, SSL_CTX **ssl_ctxs,
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
            for (size_t i=0; i<tpx_config->listeners_count; ++i)
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
                proxy_handle_timeout(proxy);
            } else {
                // timeout->key - gettime() >= 0 (from !timeout_expired),
                // and we don't create timeouts that are big enough to fill ints
                next_timeout = (int)(timeout->key - gettime());
                notimeouts = 1;
            }
        }
        
        int nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, next_timeout);
        if (nfds == -1) {
            if (errno == EINTR) {
                log_system_err(LL_WARN, "Waiting on epoll", TPX_ERR_ERRNO);
                continue;
            } else {
                _child_fatal("Waiting on epoll", TPX_ERR_ERRNO);
                return;
            }
        }

        for (size_t n=0; n < (size_t)nfds; ++n) {
            if (events[n].data.fd == sigfd) {
                struct signalfd_siginfo si;

                // This should never happen
                if (read(sigfd, &si, sizeof(si)) == -1)
                  _child_fatal("Reading sigfd", TPX_ERR_ERRNO);

                log_signal(LL_INFO, &si);

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
        errx(EXIT_FAILURE, "Config error with file '%s': %s",
             config_file, cyaml_strerror(conf_err));
        return NULL;
    } else if (tpx_validate_conf(tpx_config, NULL) != TPX_SUCCESS) {
        errx(EXIT_FAILURE, "Config file '%s' failed verification", config_file);
    }
    
    return tpx_config;
}

/** @brief Start the listener sockets (only one for now) */
listen_t **start_listeners(tpx_config_t *tpx_config, int epollfd, size_t *len,
                           SSL_CTX **ssl_ctxs) {
    *len = tpx_config->listeners_count;
    listen_t **listeners = calloc(*len, sizeof(listen_t *));
    if (!listeners)
        _child_fatal("Couldn't allocate listeners", TPX_ERR_ERRNO);
    for (size_t i=0; i < *len; ++i) {
        const tpx_listen_conf_t *lconf = &tpx_config->listeners[i];
        listeners[i] = create_listener(lconf, ssl_ctxs[i]);
        
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = listeners[i];
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listeners[i]->fd, &ev) == -1)
            _child_fatal("Couldn't add listen socket to epoll", TPX_ERR_ERRNO);

        log_listen(LL_INFO, listeners[i]);
    }
    
    return listeners;
}

void close_listeners(int epollfd, listen_t **listeners, size_t len) {
    for (size_t i=0; i<len; ++i) {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, listeners[i]->fd, NULL);
        close(listeners[i]->fd);
    }
}

void free_listeners(listen_t **listeners, size_t len) {
    for (size_t i=0; i<len; ++i)
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
        _fatal(logfd, "Couldn't set minimum TLS protocol version", TPX_ERR_OSSL);
        goto cleanup_fail;
    }

    uint64_t opts =
               SSL_OP_IGNORE_UNEXPECTED_EOF
               | SSL_OP_NO_RENEGOTIATION
               | SSL_OP_CIPHER_SERVER_PREFERENCE;
    
    SSL_CTX_set_options(ctx, opts);
    // Make sure OpenSSL buffers get released for idle connections, saves RAM
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    // For now we set the number of tickets to 1, we'll make this configurable
    // later on (issue #44)
    SSL_CTX_set_num_tickets(ctx, 1);

    if (build_chain(config, ctx, logfd) == 0) {
        _fatal(logfd, "Couldn't load cert chain", TPX_ERR_PLAIN);
        goto cleanup_fail;
    }

    // No mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;

cleanup_fail:
    SSL_CTX_free(ctx);
    return NULL;
}

/** @brief Load the server certificate into the SSL_CTX */
X509 *load_servcert(const tpx_listen_conf_t *config, int logfd) {
    BIO *leaf_bio = BIO_new_file(config->servcert, "r");
    if (leaf_bio == NULL)
    {
        _fatal(logfd, "Failed to open server cert file", TPX_ERR_OSSL);
        return NULL;
    }

    X509 *leaf = NULL;
    if (!PEM_read_bio_X509(leaf_bio, &leaf, NULL, NULL)) {
        BIO_free(leaf_bio);
        X509_free(leaf);
        _fatal(logfd, "Failed to load server cert", TPX_ERR_OSSL);
        return NULL;
    }

    BIO_free(leaf_bio);
    log_cert_load(logfd, LL_INFO, leaf, 0);

    return leaf;
}

/** @brief Load the CA certificates into a stack
 *
 *  @param[in]  config   The configuration information
 *  @param[in]  logfd    The fd which receives log messages
 *  @return 1 for success, 0 for failure
 **/
STACK_OF(X509) *load_cacerts(const tpx_listen_conf_t *config, int logfd) {
    STACK_OF(X509) *ca_certs = sk_X509_new_null();

    for (size_t i=0; i<config->cacerts_count; ++i) {
        BIO *bio = BIO_new_file(config->cacerts[i], "rb");
        if (!bio) {
            _fatal(logfd, "Couldn't allocate BIO", TPX_ERR_OSSL);
            goto cleanup;
        }

        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!cert) {
            _fatal(logfd, "Couldn't load cert file", TPX_ERR_OSSL);
            goto cleanup;
        }

        if (sk_X509_push(ca_certs, cert) == 0) {
            _fatal(logfd, "Couldn't push cert to stack", TPX_ERR_OSSL);
            X509_free(cert);
            goto cleanup;
        }

        log_cert_load(logfd, LL_INFO, cert, 0);
    }

    return ca_certs;
cleanup:
    sk_X509_pop_free(ca_certs, X509_free);
    return NULL;
}

/** @brief Load the CA certificates into a stack
 *
 *  @param[in]  config   The configuration information
 *  @param[in]  logfd    The fd which receives log messages
 *  @param[out] ca_certs CA certificates will be loaded into here
 *  @param[out] leaf     The leaf certificate will be loaded into here
 *  @return 1 for success, 0 for failure. In case of failure, caller doesn't
 *          need to free ca_certs or leaf
 **/
int load_chain_file(const tpx_listen_conf_t *config, int logfd,
                                STACK_OF(X509) **ca_certs, X509 **leaf) {
    *ca_certs = sk_X509_new_null();
    *leaf = NULL;

    int is_leaf = 1;

    BIO *bio = BIO_new_file(config->cert_chain, "rb");
    X509 *cert = NULL;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != 0) {
        log_cert_load(logfd, LL_INFO, cert, 0);

        if (is_leaf) {
            *leaf = cert;
            is_leaf = 0;
            continue;
        }

        if (sk_X509_push(*ca_certs, cert) == 0) {
            _fatal(logfd, "Couldn't push cert to stack", TPX_ERR_OSSL);
            X509_free(cert);
            goto cleanup;
        }
    }
    BIO_free(bio);
    bio = NULL;

    unsigned long err = ERR_peek_last_error();

    // If we reached EOF, just return success
    if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
        ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
        ERR_clear_error();
        return 1;
    } else {
        goto cleanup;
    }

cleanup:
    sk_X509_pop_free(*ca_certs, X509_free);
    X509_free(*leaf);
    if (bio)
        BIO_free(bio);
    return 0;
}

/** @brief Load the server private key into the SSL_CTX */
int load_servkey(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd) {
    BIO *pkey_bio = BIO_new_file(config->servkey, "r");
    if (pkey_bio == NULL)
    {
        _fatal(logfd, "Failed to open server key file", TPX_ERR_OSSL);
        return 0;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pkey_bio, NULL, NULL,
                                             (void *)config->servkeypass);
    BIO_free(pkey_bio);
    if (pkey == NULL) {
        _fatal(logfd, "Failed to read server key", TPX_ERR_OSSL);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        EVP_PKEY_free(pkey);
        _fatal(logfd, "Failed to load server key into ctx", TPX_ERR_OSSL);
        return 0;
    }

    // Our pkey is refcounted, so we should relinquish ownership
    EVP_PKEY_free(pkey);
    return 1;
}

int build_chain(const tpx_listen_conf_t *config, SSL_CTX *ctx, int logfd) {
    X509 *leaf = NULL;
    STACK_OF(X509) *ca_certs = NULL;
    STACK_OF(X509) *chain = NULL;

    if (config->cacerts != NULL) {
        if ((ca_certs = load_cacerts(config, logfd)) == NULL) {
            _fatal(logfd, "Couldn't load CA certs", TPX_ERR_PLAIN);
            goto cleanup;
        }
        if ((leaf = load_servcert(config, logfd)) == NULL) {
            _fatal(logfd, "Couldn't load server cert", TPX_ERR_PLAIN);
            goto cleanup;
        }

        // We'll fill the chain ourselves
        chain = sk_X509_new_null();
    } else if (config->cert_chain != NULL) {
        if (!load_chain_file(config, logfd, &ca_certs, &leaf)) {
            // Can't have these freed, they're guaranteed to be freed already if
            // load_chain_file returns 0
            ca_certs = NULL;
            leaf = NULL;
            _fatal(logfd, "Couldn't load certificate chain from file",
                   TPX_ERR_PLAIN);
            goto cleanup;
        }
        chain = ca_certs;
    } else {
        _fatal(logfd, "Config contains neither cert-chain nor cacerts",
               TPX_ERR_PLAIN);
        goto cleanup;
    }

    if (SSL_CTX_use_certificate(ctx, leaf) == 0) {
        _fatal(logfd, "Couldn't insert leaf cert into OpenSSL context",
               TPX_ERR_OSSL);
        goto cleanup;
    }

    if (load_servkey(config, ctx, logfd) == 0) {
        _fatal(logfd, "Couldn't load server key into OpenSSL context",
               TPX_ERR_PLAIN);
        goto cleanup;
    }

    if (chain != ca_certs) {
        X509 *cur = leaf;
        int found;
        for (;;) {
            found = 0;
            for (size_t i=0; i<sk_X509_num(ca_certs); ++i) {
                X509 *candidate = sk_X509_value(ca_certs, i);
                if (candidate != cur &&
                    X509_check_issued(candidate, cur) == X509_V_OK) {
                    sk_X509_push(chain, candidate);

                    // This is so we can pop free the ca_certs without affecting
                    // the chain, and so that we don't encounter any loops
                    sk_X509_delete(ca_certs, i);
                    cur = candidate;
                    found = 1;
                    break;
                }
            }
            if (!found)
                break;
        }

        // Whatever is left never joined the chain, so we don't send it and
        // the operator should know which one. A subject name has no length
        // we can rely on, so the subject is what gets cut and the sentence
        // around it always survives: "..." plus the tail is what says the
        // certificate was dropped rather than merely being long
        #define SUBJ_MAX 256
        static const char ignored_fmt[] = "Certificate '%.*s%s' isn't in the "
            "chain we send, so we're ignoring it";
        char ignored[sizeof(ignored_fmt) + SUBJ_MAX];

        for (int i=0; i<sk_X509_num(ca_certs); ++i) {
            char *subj = X509_NAME_oneline(
                    X509_get_subject_name(sk_X509_value(ca_certs, i)), NULL, 0);
            const char *name = subj == NULL ? "(unreadable subject)" : subj;

            snprintf(ignored, sizeof(ignored), ignored_fmt, SUBJ_MAX, name,
                     strlen(name) > SUBJ_MAX ? "..." : "");
            OPENSSL_free(subj);

            log_system_err_m_ex(logfd, LL_WARN, "Certificate isn't in chain",
                                ignored);
            fprintf(stderr, "%s\n", ignored);
        }
        #undef SUBJ_MAX

        sk_X509_pop_free(ca_certs, X509_free);
    }

    // In either case, we no longer need the leaf, we've given it to the SSL_CTX
    X509_free(leaf);
    // Set them to NULL so they're not double freed
    leaf = NULL;
    // If we're using cacerts, this is already free. If we're using the
    // cert-chain, set this to NULL so that only chain is freed in cleanup
    ca_certs = NULL;

    if (SSL_CTX_set0_chain(ctx, chain) == 0) {
        _fatal(logfd, "Couldn't insert cert chain into OpenSSL context",
               TPX_ERR_OSSL);
        goto cleanup;
    }

    return 1;

cleanup:
    X509_free(leaf);

    sk_X509_pop_free(ca_certs, X509_free);
    sk_X509_pop_free(chain, X509_free);

    return 0;
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

    if (tpx_validate_conf(new_config, logfd) == TPX_FAILURE)
        goto failure;

    int new_logfd = -1;
    pid_t *new_pids = NULL;

    for (size_t i=0; i<new_config->listeners_count; ++i) {
        // We don't actually use this context we've made, we just want to
        // prove that it will be made without errors
        SSL_CTX *ssl_ctx = init_openssl(&new_config->listeners[i], *logfd);
        if (!ssl_ctx) {
            log_system_err_m_ex(*logfd, LL_ERROR, "Couldn't reload config",
                               "Couldn't initialize OpenSSL");
            goto failure;
        }
        SSL_CTX_free(ssl_ctx);
    }

    // Do this before clearing our old config, because it can fail
    new_pids = calloc((*config)->nworkers, sizeof(pid_t));
    if (!new_pids) {
        perror("Couldn't allocate PID list");
        goto failure;
    }

    new_logfd = init_logger(new_config);

    // We're mostly sure our config is good, so let's start up the new log
    if (new_logfd == -2) {
        log_system_err_m(*logfd, LL_ERROR, "Couldn't update logfile",
                         TPX_ERR_ERRNO);
        goto failure;
    } else if (new_logfd == -1) {
        g_shmem->logger.enabled = 0;
    } else {
        g_shmem->logger.enabled = 1;
        if (new_config->loglevel)
            g_shmem->logger.loglevel = *new_config->loglevel;
        else
            g_shmem->logger.loglevel = LL_INFO;
    }

    // Now we're fully convinced our new config is good
    size_t old_workers = (*config)->nworkers;
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t *)*config, 0);
    close(*logfd);

    *config = new_config;
    *logfd = new_logfd;

    for (size_t i=0; i<old_workers; ++i)
        kill_safe((*pids)[i], SIGHUP);
    left_to_close = old_workers;
    free(*pids);
    *pids = new_pids;

    check_keyfiles(*logfd, *config);

    return 1;

failure:
    free(new_pids);
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t *)new_config, 0);
    return 0;
}


tpx_err_t handle_signal(struct signalfd_siginfo *si,
                        tpx_config_t **config_,
                        int *logfd_,
                        pid_t **pids_) {
    uint8_t finishing = 0;
    int logfd = logfd_ ? *logfd_ : -1;
    tpx_config_t *config = *config_;
    pid_t *pids = *pids_;

    log_signal_m(logfd, LL_INFO, si);

    if (si->ssi_signo == SIGCHLD) {
        // Don't want to leave any zombies
        pid_t pid = -1;
        int wstatus = 0;
        while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
            log_worker(logfd, LL_WARN, TPX_WORKER_DEAD, pid, wstatus);

            if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == TPX_WORKER_FATAL) {
                for (size_t i=0; i<config->nworkers; ++i)
                    kill_safe(pids[i], SIGKILL);
                exit(TPX_WORKER_FATAL);
            }

            for (size_t i=0; i<config->nworkers; ++i) {
                if (pids[i] == pid) {
                    if (in_shutdown) {
                        --left_to_close;
                    } else {
                        // A worker has shut down
                        uint64_t now = gettime();
                        if (now - window_start >
                            TPX_RESTART_WINDOW * 1000) {

                            window_start = now;
                            restarts = 0;
                        }

                        if (++restarts > TPX_RESTART_MAX*config->nworkers) {
                            log_system_err_m(logfd, LL_FATAL,
                                             "Workers dying faster than they can be replaced",
                                             TPX_ERR_PLAIN);
                            fprintf(stderr,"Error: Workers dying faster than they can be replaced\n");

                            for (size_t i=0; i<config->nworkers; ++i)
                                kill_safe(pids[i], SIGKILL);
                            exit(TPX_WORKER_FATAL);
                        }
                        respawn = 1;
                        finishing = 1;
                    }
                    pids[i] = -1;
                    break;
                }
            }
        }

        return finishing ? TPX_CLOSED : TPX_SUCCESS;
    } else if (si->ssi_signo == SIGHUP) {
        if (handle_reload(config_, logfd_, pids_) == 1)
            return TPX_CLOSED;
        return TPX_SUCCESS;
    } else if (si->ssi_signo == SIGPIPE) {
        // All my homies hate SIGPIPE
        return TPX_SUCCESS;
    }

    in_shutdown = 1;
    left_to_close = config->nworkers;
    for (size_t i=0; i<left_to_close; ++i)
        kill_safe(pids[i], SIGHUP);

    return TPX_SUCCESS;
}
