#include "listen.h"

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "errors.h"
#include "event.h"
#include "proxy.h"


tpx_err_t handle_accept(listen_t *listen, int epollfd, uint32_t events,
                        void *ssl_ctx, unsigned int conn_timeout) {
    assert(listen->event_id == EV_LISTEN);
    
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    int conn_sock = accept(listen->fd, (struct sockaddr *) &addr,
                           &addrlen);
    if (conn_sock == -1) {
        perror("handle_accept: accept");
        return TPX_FAILURE;
    }

    int sock_flags;
    if ((sock_flags = fcntl(conn_sock, F_GETFL)) == -1) {
        perror("handle_accept: fcntl(GETFL)");
        return TPX_FAILURE;
    }
    if (fcntl(conn_sock, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
        perror("handle_accept: fcntl(SETFL)");
        return TPX_FAILURE;
    }

    SSL *ssl = SSL_new((SSL_CTX *)ssl_ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "handle_accept: SSL_new: Couldn't create SSL ctx\n");
        return TPX_FAILURE;
    }

    if (SSL_set_fd(ssl, conn_sock) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        fprintf(stderr, "handle_accept: SSL_set_fd: Couldn't assign sock\n");
        return TPX_FAILURE;
    }

    SSL_set_accept_state(ssl);

    // Programmer beware: Make 100% sure that addr gets copied into the proxy
    // ctx rather than just its pointer.
    proxy_t *proxy = create_proxy(conn_sock, ssl,
                                  listen, conn_timeout);
    if (!proxy) {
        SSL_free(ssl);
        fprintf(stderr, "handle_accept: Couldn't create proxy\n");
        return TPX_FAILURE;
    }

    tpx_err_t retval = proxy_add_to_epoll(proxy, epollfd);
    if (retval == TPX_FAILURE) {
        // Need to call with epollfd=-1 to show that the sockets aren't in epoll
        proxy_close(proxy, -1);
        fprintf(stderr, "handle_accept: Couldn't add sockets to epoll, not making proxy\n");
        return TPX_FAILURE;
    }
    return retval;
}

listen_t *create_listener(const char *lhost, const unsigned short lport,
                          const char *thost, const unsigned short tport) {
    listen_t *l = malloc(sizeof(listen_t));
    if (!l)
        err(EXIT_FAILURE, "create_listener: malloc");
    
    int lsock = bind_listen_sock(l, lhost, lport);
    
    if (listen(lsock, SOMAXCONN) < 0)
        err(EXIT_FAILURE, "create_listener: listen");

    l->event_id = EV_LISTEN;
    l->fd = lsock;
    tpx_err_t ret = get_conn(thost, tport,
                             (struct sockaddr *)&l->peer_addr,
                             &l->peer_addrlen);
    if (ret == TPX_FAILURE) {
        close(lsock);
        free(l);
        errx(EXIT_FAILURE, "create_listener: Couldn't make listener");
    }

    return l;
}

int bind_listen_sock(listen_t *l, const char *host,
                     const unsigned short port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char service[6];
    snprintf(service, sizeof(service), "%d", port);
    
    struct addrinfo *listen_addr, *lp;
    int gai_err = getaddrinfo(host, service, &hints, &listen_addr);
    if (gai_err != 0)
        errx(EXIT_FAILURE, "bind_listen_sock: getaddrinfo (%s:%d): %s",
             host, port, gai_strerror(gai_err));

    int fd = -1;
    int opt = 0;
    for (lp = listen_addr; lp != NULL; lp = lp->ai_next) {
        fd = socket(lp->ai_family, lp->ai_socktype, lp->ai_protocol);
        if (fd == -1) {
            perror("bind_listen_sock: socket");
            continue;
        }

        opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                       &opt, sizeof(opt)))
            err(EXIT_FAILURE, "bind_listen_sock: setsockopt (reuse)");
        opt = 0;
        if (lp->ai_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6,
                                                    IPV6_V6ONLY, &opt,
                                                    sizeof(opt)))
            err(EXIT_FAILURE, "bind_listen_sock: setsockopt (ipv6)");

        if (bind(fd, lp->ai_addr, lp->ai_addrlen) < 0) {
            perror("bind_listen_sock: bind");
        } else {
            break;
        }

        close(fd);
    }
    if (lp == NULL || fd == -1) {
        freeaddrinfo(listen_addr);
        errx(EXIT_FAILURE, "Couldn't bind on any addresses");
    }

    memcpy(&l->listen_addr, lp->ai_addr, lp->ai_addrlen);
    l->listen_addrlen = lp->ai_addrlen;

    freeaddrinfo(listen_addr);
    return fd;
}

tpx_err_t get_conn(const char *host, const unsigned short port,
                   struct sockaddr *addr, socklen_t *len) {
    char service[6];
    snprintf(service, sizeof(service), "%d", port);
    
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    struct addrinfo *connect_addr;
    int error = getaddrinfo(host, service, &hints, &connect_addr);
    if (error != 0) {
        fprintf(stderr, "getaddrinfo for listener (%s:%hu) failed: %s\n",
                host, port, gai_strerror(error));
        return TPX_FAILURE;
    }

    memcpy(addr, connect_addr->ai_addr, connect_addr->ai_addrlen);
    *len = connect_addr->ai_addrlen;
    
    freeaddrinfo(connect_addr);
    return TPX_SUCCESS;
}
