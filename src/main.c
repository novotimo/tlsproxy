#include <err.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "config.h"
#include "connection.h"
#include "errors.h"
#include "proxy.h"


#define TPX_MAX_EVENTS 100


static const cyaml_config_t cyaml_config = {
	.log_fn = cyaml_log,
	.mem_fn = cyaml_mem,
	.log_level = CYAML_LOG_WARNING,
};

void usage(char *progname) {
    fprintf(stderr, "Usage: %s <config.yml>\n", progname);
    exit(EXIT_FAILURE);
}

SSL_CTX *init_openssl(tpx_config_t *config) {
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to create OpenSSL CTX");
    }

    // I'll make these configurable eventually
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(EXIT_FAILURE, "init_openssl: Failed to set mininimum TLS "
             "protocol version to TLS 1.2");
    }

    int opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
    opts |= SSL_OP_NO_RENEGOTIATION;
    opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
    
    SSL_CTX_set_options(ctx, opts);

    // Load cacerts
    int use_cacerts = config->cacerts != NULL;

    if (use_cacerts) {
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
        
        X509 *cert;
        for (int i=0; i<config->cacerts_count; ++i) {
            cert = NULL;
            BIO *bio = BIO_new_file(config->cacerts[i], "r");
            if (!PEM_read_bio_X509(bio, &cert, NULL, NULL)) {
                ERR_print_errors_fp(stderr);
                BIO_free(bio);
                errx(EXIT_FAILURE, "init_openssl: Failed to load cert file '%s'",
                     config->cacerts[i]);
            }
            BIO_free(bio);
            
            printf("Loaded chain cert '%s'\n", config->cacerts[i]);
            if (SSL_CTX_add0_chain_cert(ctx, cert) != 1) {
                SSL_CTX_free(ctx);
                ERR_print_errors_fp(stderr);
                errx(EXIT_FAILURE, "init_openssl: Failed to add cert '%s' to the "
                     "CTX", config->cacerts[i]);
            }
        }

        if (SSL_CTX_build_cert_chain(ctx, SSL_BUILD_CHAIN_FLAG_UNTRUSTED | SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR) != 1) {
            SSL_CTX_free(ctx);
            ERR_print_errors_fp(stderr);
            errx(EXIT_FAILURE, "init_openssl: Failed to build cert chain");
        }
    } else {
        if (SSL_CTX_use_certificate_chain_file(ctx, config->cert_chain) != 1) {
            SSL_CTX_free(ctx);
            ERR_print_errors_fp(stderr);
            errx(EXIT_FAILURE, "init_openssl: Failed to load cert chain from "
                 "'%s'", config->cert_chain);
        }
    }

    // Load servkey
    BIO *pkey_bio = BIO_new_file(config->servkey, "r");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(
        pkey_bio, NULL, NULL, (void *)config->servkeypass);
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

    // No mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

int main(int argc, char *argv[]) {
    printf("TLS Proxy starting\n");

    
    if (argc != 2)
        usage(argv[0]);

    char *config_file = argv[1];
    tpx_config_t *tpx_config;

    cyaml_err_t conf_err =
        cyaml_load_file(config_file, &cyaml_config, &top_schema,
                        (cyaml_data_t **)&tpx_config, NULL);
    if (conf_err != CYAML_OK) {
        errx(EXIT_FAILURE, "%s", cyaml_strerror(conf_err));
    } else if (tpx_validate_conf(tpx_config) != TPX_SUCCESS) {
        errx(EXIT_FAILURE, "Config file '%s' failed verification", config_file);
    }
    
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ssl_ctx = init_openssl(tpx_config);

    struct epoll_event events[TPX_MAX_EVENTS];

    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        err(EXIT_FAILURE, "epoll_create1");

    connection_t *listener =
        tpx_proxy_listen(tpx_config->listen_ip,tpx_config->listen_port,
                         tpx_config->target_ip, tpx_config->target_port);
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = listener;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->fd, &ev) == -1)
        err(EXIT_FAILURE, "epoll_ctl: listen_sock");

    int nfds;
    tpx_err_t handle_err = TPX_SUCCESS;
    for (;;) {
        nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);
        for (size_t n=0; n < nfds; ++n) {
            handle_err = tpx_proxy_handle_all(events[n].data.ptr,
                                              epollfd, events[n].events,
                                              ssl_ctx);
            if (handle_err != TPX_SUCCESS)
                tpx_proxy_close(events[n].data.ptr, epollfd);
        }
    }

    return(EXIT_SUCCESS);
}
