#include "main.h"

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
        
        /*

        // Find root
        STACK_OF(X509) *chain;
        if (SSL_CTX_get0_chain_certs(ctx, &chain) != 1) {
            SSL_CTX_free(ctx);
            ERR_print_errors_fp(stderr);
            errx(EXIT_FAILURE, "init_openssl: Failed to get chain certs");
        }
        X509 *cur = leaf;
        int issuer_exists = 1;
        for (;;) {
            X509_NAME *issuer_name = X509_get_issuer_name(cur);
            issuer_exists = 0;

            // Let's just say self-signed certs have no issuer
            if (X509_name_cmp(X509_get_subject_name(cur), issuer_name) == 0) {
                break;
            }
            
            for (int i=0; i<sk_X509_num(chain); ++i) {
                X509 *c = sk_X509_value(chain, i);
                if (X509_name_cmp(X509_get_subject_name(c), issuer_name) == 0) {
                    cur = c;
                    issuer_exists = 1;
                    break;
                }
            }
            if (!issuer_exists)
                break;
        }

        printf("Found CA cert: ");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cur), 0, 0);
        printf("\n");
        
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_add_cert(store, cur);
        */

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

    SSL_CTX *ssl_ctx = init_openssl(tpx_config);

    signal(SIGPIPE, SIG_IGN);

    struct epoll_event events[TPX_MAX_EVENTS];

    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        err(EXIT_FAILURE, "epoll_create1");

    connection_t *listener =
        tpx_create_listener(tpx_config->listen_ip,tpx_config->listen_port);
    
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
            handle_err = tpx_handle_all(events[n].data.ptr,
                                        epollfd, events[n].events,
                                        ssl_ctx);
            if (handle_err != TPX_SUCCESS)
                tpx_conn_close(events[n].data.ptr, epollfd);
        }
    }
    
    return(EXIT_SUCCESS);
}
