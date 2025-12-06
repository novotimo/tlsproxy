#include <err.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>

#include "config.h"
#include "errors.h"
#include "event.h"
#include "listen.h"
#include "proxy.h"


#define TPX_MAX_EVENTS 100 /**< @brief The maximum number of events in epoll */
#define TPX_NARGS 2 /**< @brief The number of arguments to this program */
#define TPX_ARG_CONFFILE 1 /**< @brief The config file argument */

#define NAME closed /**< @brief The name of the hash set */
#define KEY_TY uint64_t /**< @brief The key type of the hash set */
#define HASH_FN vt_hash_integer /**< @brief The hash function of */
#define CMPR_FN vt_cmpr_integer /**< @brief The compare function */
#include "verstable.h"


void usage(const char *prog);
void main_loop(int epollfd, SSL_CTX *ssl_ctx);
tpx_config_t *load_config(const char *conf_file);
void start_listeners(tpx_config_t *config, int epollfd);
static inline uint64_t del_tag(void *ptr);

SSL_CTX *init_openssl(tpx_config_t *config);
void load_servcert(tpx_config_t *config, SSL_CTX *ctx);
void load_cacerts(tpx_config_t *config, SSL_CTX *ctx);
void load_servkey(tpx_config_t *config, SSL_CTX *ctx);


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

/** @brief Inits OpenSSL and epoll then passes to main loop */
int main(int argc, char *argv[]) {
    printf("TLS Proxy starting\n");
    
    if (argc != TPX_NARGS)   
        usage(argv[0]);

    tpx_config_t *tpx_config = load_config(argv[TPX_ARG_CONFFILE]);

    /* I hate SIGPIPE! */
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ssl_ctx = init_openssl(tpx_config);

    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        err(EXIT_FAILURE, "epoll_create1");

    start_listeners(tpx_config, epollfd);

    main_loop(epollfd, ssl_ctx);

    return(EXIT_SUCCESS);
}

/** @brief The main loop waits on epoll and dispatches events */
void main_loop(int epollfd, SSL_CTX *ssl_ctx) {
    struct epoll_event events[TPX_MAX_EVENTS];
    closed closed_set;
    closed_init(&closed_set);
    
    for (;;) {
        int nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);
        for (size_t n=0; n < nfds; ++n) {
            closed_itr it = closed_get(&closed_set,
                                       del_tag(events[n].data.ptr));
            if (!closed_is_end(it))
                continue;
            
            tpx_err_t ev_ret = dispatch_events(events[n].data.ptr, epollfd,
                                               events[n].events, ssl_ctx);
            if (ev_ret == TPX_CLOSED) {
                it = closed_insert(&closed_set, del_tag(events[n].data.ptr));
                if (closed_is_end(it)) {
                    errx(EXIT_FAILURE, "main_loop: Ran out of memory for "
                         "hash table");
                }
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
    if (conf_err != CYAML_OK)
        errx(EXIT_FAILURE, "Config error: %s", cyaml_strerror(conf_err));
    else if (tpx_validate_conf(tpx_config) != TPX_SUCCESS)
        errx(EXIT_FAILURE, "Config file '%s' failed verification", config_file);
    
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
        err(EXIT_FAILURE, "epoll_ctl: listen_sock");
}

/** @brief Inits SSL_CTX for use as a TLS server, loading certs */
SSL_CTX *init_openssl(tpx_config_t *config) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to create OpenSSL CTX");
    }

    // TODO: make the ciphersuites and accepted TLS versions configurable
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to set mininimum TLS "
             "protocol version to TLS 1.2");
    }

    int opts =
        SSL_OP_IGNORE_UNEXPECTED_EOF
        | SSL_OP_NO_RENEGOTIATION
        | SSL_OP_CIPHER_SERVER_PREFERENCE;
    
    SSL_CTX_set_options(ctx, opts);

    if (config->cacerts != NULL) {
        load_servcert(config, ctx);
        load_cacerts(config, ctx);
    } else if (config->cert_chain != NULL) {
        if (SSL_CTX_use_certificate_chain_file(ctx, config->cert_chain) != 1) {
            SSL_CTX_free(ctx);
            ERR_print_errors_fp(stderr);
            errx(EXIT_FAILURE, "init_openssl: Failed to load cert chain from "
                 "'%s'", config->cert_chain);
        }
        printf("Loaded cert chain from file '%s'\n", config->cert_chain);
    } else {
        errx(EXIT_FAILURE, "A programmer error occurred: managed to get a "
             "config with both cert-chain and cacerts NULL!");
    }

    int flags = config->cacerts == NULL
                    ? SSL_BUILD_CHAIN_FLAG_UNTRUSTED |
                      SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR
                    : 0;

    if (SSL_CTX_build_cert_chain(ctx, flags) != 1) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to build cert chain");
    }
    printf("Successfully built and verified cert chain\n");

    load_servkey(config, ctx);

    // No mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

/** @brief Load the server certificate into the SSL_CTX */
void load_servcert(tpx_config_t *config, SSL_CTX *ctx) {
    BIO *leaf_bio = BIO_new_file(config->servcert, "r");
    X509 *leaf = NULL;
    if (!PEM_read_bio_X509(leaf_bio, &leaf, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        BIO_free(leaf_bio);
        errx(EXIT_FAILURE, "init_openssl: Failed to load servcert '%s'",
             config->servcert);
    }
    BIO_free(leaf_bio);
    printf("Loaded leaf cert '%s'\n", config->servcert);
        
    if (SSL_CTX_use_certificate(ctx, leaf) != 1) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to add servcert to CTX");
    }
}

/** @brief Load the CA certificates into the SSL_CTX */
void load_cacerts(tpx_config_t *config, SSL_CTX *ctx) {
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    for (int i=0; i<config->cacerts_count; ++i) {
        X509_LOOKUP_load_file(lookup, config->cacerts[i], X509_FILETYPE_PEM);
        printf("Loaded chain cert '%s'\n", config->cacerts[i]);
    }

    SSL_CTX_set_cert_store(ctx, store);
}

/** @brief Load the server private key into the SSL_CTX */
void load_servkey(tpx_config_t *config, SSL_CTX *ctx) {
    BIO *pkey_bio = BIO_new_file(config->servkey, "r");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pkey_bio, NULL, NULL,
                                             (void *)config->servkeypass);
    BIO_free(pkey_bio);
    if (pkey == NULL) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to read server key from "
             "'%s'", config->servkey);
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to load server key into CTX");
    }
}
