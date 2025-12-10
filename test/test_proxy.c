#include "proxy.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "macros.h"
#include "event.h"


// Declare wrapped functions that follow the simplest pattern
#define WRAPPED_FUNCS \
    WRAP_FUN(socket, int, (int domain, int type, int protocol),      \
             (domain, type, protocol))                               \
    WRAP_FUN(malloc, void *, (const size_t size), (size))            \
    WRAP_FUN(free, void, (void *p), (p))            \
    WRAP_FUN(SSL_free, void, (SSL *p), (p))            \
    WRAP_FUN(SSL_shutdown, int, (SSL *p), (p))            \
    WRAP_FUN_ERR(connect, int, (int sockfd, const struct sockaddr *addr, \
                                socklen_t addrlen),                      \
                 (sockfd, addr, addrlen)) \
    WRAP_FUN_ERR(close, int, (int sockfd), (sockfd)) \
    WRAP_FUN(epoll_ctl, int, (int efd, int op, int fd, struct epoll_event *e), \
                 (efd, op, fd, e)) \
    WRAP_FUN_ERR(send, ssize_t, \
                 (int sockfd, const void *buf, size_t size, int flags), \
                 (sockfd, buf, size, flags))                            \
    WRAP_FUN(SSL_write, ssize_t, \
             (SSL *ssl, const void *buf, int num), \
             (ssl, buf, num)) \
    WRAP_FUN_ERR(read, ssize_t, \
                 (int sockfd, void *buf, size_t size), \
                 (sockfd, buf, size))                            \
    WRAP_FUN(SSL_read, ssize_t, \
             (SSL *ssl, void *buf, int num), \
             (ssl, buf, num)) \
    WRAP_FUN(SSL_get_error, int, (const SSL *ssl, int ret), (ssl, ret)) \
    WRAP_FUN(queue_peek, int, \
             (bufq_t *q, unsigned char **buf, size_t *buflen),  \
             (q, buf, buflen)) \
    WRAP_FUN(queue_peek_last, int, \
             (bufq_t *q, unsigned char **buf, size_t *buflen),  \
             (q, buf, buflen)) \
    WRAP_FUN(ngx_rbtree_delete, void, \
             (ngx_rbtree_t *tree, ngx_rbtree_node_t *node),     \
             (tree, node)) \
    WRAP_FUN(ngx_rbtree_insert, void, \
             (ngx_rbtree_t *tree, ngx_rbtree_node_t *node),     \
             (tree, node))

WRAPPED_FUNCS
#undef WRAP_FUN

// Need to handle varargs separately
int __real_fcntl(int fd, int op, ...);
int __wrap_fcntl(int fd, int op, ...) {
    if (has_mock())
        return (int) mock();
    else {
        va_list args;
        va_start(args, op);
    
        int res = __real_fcntl(fd, op, args);
        va_end(args);
        return res;
    }
}


static void test_create_proxy(void **state) {
    int accept_sock = 42;
    int conn_sock = 43;
    SSL *ssl = (SSL *)0x47;
    will_return(__wrap_socket, conn_sock);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_ngx_rbtree_delete, NULL);
    
    struct sockaddr sa;
    proxy_t *p = create_proxy(accept_sock, ssl, (struct sockaddr *)&sa,
                              sizeof(struct sockaddr), 5);
    assert_non_null(p);
    assert_int_equal(p->event_id, EV_PROXY);
    assert_non_null(p->c2s);
    assert_non_null(p->s2c);
    assert_int_equal(p->client_fd, accept_sock);
    assert_int_equal(p->serv_fd, conn_sock);
    assert_ptr_equal(p->ssl, ssl);
    assert_int_equal(p->server_addrlen, sizeof(struct sockaddr));
    assert_int_equal(p->state, PS_READY);
    proxy_close(p, -1);
}

static void test_create_proxy_again(void **state) {
    int accept_sock = 42;
    int conn_sock = 43;
    SSL *ssl = (SSL *)0x47;
    will_return(__wrap_socket, conn_sock);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINPROGRESS);
    will_return(__wrap_ngx_rbtree_insert, NULL);
    
    struct sockaddr sa;
    proxy_t *p = create_proxy(accept_sock, ssl, (struct sockaddr *)&sa,
                              sizeof(struct sockaddr), 5);
    assert_non_null(p);
    assert_int_equal(p->event_id, EV_PROXY);
    assert_non_null(p->c2s);
    assert_non_null(p->s2c);
    assert_int_equal(p->client_fd, accept_sock);
    assert_int_equal(p->serv_fd, conn_sock);
    assert_ptr_equal(p->ssl, ssl);
    assert_int_equal(p->server_addrlen, sizeof(struct sockaddr));
    assert_int_equal(p->state, PS_SERVER_CONNECTING);
    
    will_return(__wrap_ngx_rbtree_delete, NULL);
    will_return(__wrap_SSL_free, NULL);
    proxy_close(p, -1);
}

static void test_create_proxy_connerr(void **state) {
    int accept_sock = 42;
    int conn_sock = 43;
    SSL *ssl = (SSL *)0x47;
    will_return(__wrap_socket, conn_sock);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINVAL);
    will_return(__wrap_close, NULL);
    
    struct sockaddr sa;
    proxy_t *p = create_proxy(accept_sock, ssl, (struct sockaddr *)&sa,
                              sizeof(struct sockaddr), 5);
    assert_null(p);
}

static void test_create_proxy_bad_malloc(void **state) {
    int accept_sock = 42;
    SSL *ssl = (SSL *)0x47;
    will_return(__wrap_malloc, NULL);
    
    struct sockaddr sa;
    proxy_t *p = create_proxy(accept_sock, ssl, (struct sockaddr *)&sa,
                              sizeof(struct sockaddr), 5);
    assert_null(p);
}

static void test_create_conn_bad_sock(void **state) {
    will_return(__wrap_socket, -1);
    proxy_t p;
    assert_int_equal(create_connect(&p), -1);
}

static void test_create_conn_fcntl1(void **state) {
    will_return(__wrap_socket, 50);
    will_return(__wrap_fcntl, -1);
    proxy_t p;
    assert_int_equal(create_connect(&p), -1);
}

static void test_create_conn_fcntl2(void **state) {
    will_return(__wrap_socket, 50);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, -1);
    proxy_t p;
    assert_int_equal(create_connect(&p), -1);
}

static void test_pa2e_success(void **state) {
    proxy_t p;
    will_return(__wrap_epoll_ctl, 0);
    will_return(__wrap_epoll_ctl, 0);
    assert_int_equal(proxy_add_to_epoll(&p, 7),TPX_SUCCESS);
}

static void test_pa2e_fail1(void **state) {
    proxy_t p;
    will_return(__wrap_epoll_ctl, 0);
    will_return(__wrap_epoll_ctl, -1);
    assert_int_equal(proxy_add_to_epoll(&p, 7),TPX_FAILURE);
}

static void test_pa2e_fail2(void **state) {
    proxy_t p;
    will_return(__wrap_epoll_ctl, -1);
    assert_int_equal(proxy_add_to_epoll(&p, 7),TPX_FAILURE);
}

static void test_proxy_close_ssl(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_CLIENT_DISCONNECTED;
    p->ssl = (SSL *)0x7;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;
    
    will_return(__wrap_SSL_free, NULL);
    assert_int_equal(proxy_close(p,-1), TPX_CLOSED);
}

static void test_proxy_close_again(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_SERVER_DISCONNECTED;
    p->ssl = (SSL *)0x7;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;
    
    will_return(__wrap_SSL_shutdown, 0);
    assert_int_equal(proxy_close(p,-1), TPX_AGAIN);
}

static void test_proxy_close_shutdown_done(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_SERVER_DISCONNECTED;
    p->ssl = (SSL *)0x7;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;
    
    will_return(__wrap_SSL_shutdown, 1);
    will_return(__wrap_SSL_free, NULL);
    assert_int_equal(proxy_close(p,-1), TPX_CLOSED);
}

static void test_proxy_close_nossl(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_SERVER_DISCONNECTED;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;
    
    assert_int_equal(proxy_close(p,-1), TPX_CLOSED);
}

static void test_proxy_close_epoll(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_CLIENT_DISCONNECTED;
    p->ssl = NULL;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = 7;
    p->client_fd = 8;
    
    will_return(__wrap_epoll_ctl, -1);
    will_return(__wrap_epoll_ctl, -1);
    assert_int_equal(proxy_close(p,1), TPX_CLOSED);

    p = malloc(sizeof(proxy_t));
    p->state = PS_CLIENT_DISCONNECTED;
    p->ssl = NULL;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = 7;
    p->client_fd = 8;
    
    will_return(__wrap_epoll_ctl, 0);
    will_return(__wrap_epoll_ctl, -1);
    assert_int_equal(proxy_close(p,1), TPX_CLOSED);

    p = malloc(sizeof(proxy_t));
    p->state = PS_CLIENT_DISCONNECTED;
    p->ssl = NULL;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = 7;
    p->client_fd = 8;
    
    will_return(__wrap_epoll_ctl, 0);
    will_return(__wrap_epoll_ctl, 0);
    assert_int_equal(proxy_close(p,1), TPX_CLOSED);    
}

static void test_handle_proxy_cc(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_CLIENT_CONNECTED;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // If connect returns EINPROGRESS let's call connect again later
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINPROGRESS);
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_AGAIN);
    assert_int_equal(p->state, PS_SERVER_CONNECTING);

    // If connect returns 0 and there were no epoll events
    p->state = PS_CLIENT_CONNECTED;
    will_return(__wrap_connect, 0);
    will_return(__wrap_ngx_rbtree_delete, NULL);
    // Need EPOLLPRI here because we assert that we always have events
    assert_int_equal(handle_proxy(p, -1, EPOLLPRI, NULL, 0, 5),TPX_SUCCESS);
    assert_int_equal(p->state, PS_READY);

    // If connect returns EINVAL
    p->state = PS_CLIENT_CONNECTED;
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINVAL);
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_CLOSED);
    // p is freed
}

static void test_handle_proxy_sc(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_SERVER_CONNECTING;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // If connect returns EINPROGRESS let's call connect again later
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINPROGRESS);
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_AGAIN);
    assert_int_equal(p->state, PS_SERVER_CONNECTING);

    // If connect returns 0 and there were no epoll events
    p->state = PS_SERVER_CONNECTING;
    // Need EPOLLPRI here because we assert that we always have events
    assert_int_equal(handle_proxy(p, -1, EPOLLPRI, NULL, 1, 5),TPX_SUCCESS);
    assert_int_equal(p->state, PS_SERVER_CONNECTING);

    // If connect returns EINVAL
    p->state = PS_SERVER_CONNECTING;
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINVAL);
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_CLOSED);
    // p is freed
}

static void test_handle_proxy_ready_s(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // EPOLLOUT
    // empty outbuf

    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 0, 5),TPX_SUCCESS);

    // 1 chunk in outbuf
    p->state = PS_READY;
    unsigned char *buf = malloc(10);
    strcpy((char *)buf, "asdf");
    size_t buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->c2s, buf, buflen+1),TPX_SUCCESS);
    p->c2s->write_idx = buflen;
    will_return(__wrap_send, buflen);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 0, 5),TPX_SUCCESS);
    queue_free(p->c2s);
    p->c2s = queue_new();

    // 2 chunks
    p->state = PS_READY;
    unsigned char *buf1 = malloc(5);
    unsigned char *buf2 = malloc(6);
    strcpy((char *)buf1, "asdf");
    strcpy((char *)buf2, "asdf");
    buflen = strlen((char *)buf1);
    assert_int_equal(enqueue(p->c2s, buf1, buflen),TPX_SUCCESS);
    assert_int_equal(enqueue(p->c2s, buf2, 6),TPX_SUCCESS);
    p->c2s->write_idx = buflen;
    will_return(__wrap_send, buflen);
    will_return(__wrap_send, 0);
    will_return(__wrap_send, -1);
    will_return(__wrap_send, EAGAIN);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 0, 5),TPX_SUCCESS);
    queue_free(p->c2s);
    p->c2s = queue_new();

    // broken queue
    p->state = PS_READY;
    buf = malloc(10);
    strcpy((char *)buf, "asdf");
    buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->c2s, buf, buflen+1),TPX_SUCCESS);
    p->c2s->write_idx = buflen;
    p->ssl = (SSL *)0x7;
    will_return(__wrap_queue_peek, TPX_FAILURE);
    will_return(__wrap_SSL_shutdown, 0);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 0, 5),TPX_SUCCESS);
    queue_free(p->c2s);
    p->c2s = queue_new();

    // broken queue, proxy_close succeeds
    p->state = PS_READY;
    buf = malloc(10);
    strcpy((char *)buf, "asdf");
    buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->c2s, buf, buflen+1),TPX_SUCCESS);
    p->c2s->write_idx = buflen;
    p->ssl = (SSL *)0x7;
    will_return(__wrap_queue_peek, TPX_FAILURE);
    will_return(__wrap_SSL_shutdown, 1);
    will_return(__wrap_SSL_free, NULL);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 0, 5),TPX_CLOSED);
    // Frees proxy
}

static void test_handle_proxy_ready_c(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // EPOLLOUT
    // empty outbuf
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 1, 5),TPX_SUCCESS);

    // 1 chunk in outbuf
    unsigned char *buf = malloc(10);
    strcpy((char *)buf, "asdf");
    size_t buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->s2c, buf, buflen+1),TPX_SUCCESS);
    p->s2c->write_idx = buflen;
    will_return(__wrap_SSL_write, buflen);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 1, 5),TPX_SUCCESS);
    queue_free(p->s2c);
    p->s2c = queue_new();

    // 2 chunks
    unsigned char *buf1 = malloc(5);
    unsigned char *buf2 = malloc(6);
    strcpy((char *)buf1, "asdf");
    strcpy((char *)buf2, "asdf");
    buflen = strlen((char *)buf1);
    assert_int_equal(enqueue(p->s2c, buf1, buflen),TPX_SUCCESS);
    assert_int_equal(enqueue(p->s2c, buf2, 6),TPX_SUCCESS);
    p->s2c->write_idx = buflen;
    will_return(__wrap_SSL_write, buflen);
    will_return(__wrap_SSL_get_error, SSL_ERROR_NONE);
    will_return(__wrap_SSL_write, buflen);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 1, 5),TPX_SUCCESS);
    queue_free(p->s2c);
    p->s2c = queue_new();

    // broken queue
    buf = malloc(10);
    strcpy((char *)buf, "asdf");
    buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->s2c, buf, buflen+1),TPX_SUCCESS);
    p->s2c->write_idx = buflen;
    will_return(__wrap_queue_peek, TPX_FAILURE);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 1, 5),TPX_CLOSED);
    // Frees proxy
}

static void test_handle_proxy_sslerr(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    unsigned char *buf = malloc(10);
    strcpy((char *)buf, "asdf");
    size_t buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->s2c, buf, buflen+1),TPX_SUCCESS);
    p->s2c->write_idx = buflen;
    will_return(__wrap_SSL_write, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_SYSCALL);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 1, 5),TPX_CLOSED);
}

static void test_handle_proxy_senderr(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->c2s = queue_new();
    p->s2c = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    unsigned char *buf = malloc(10);
    strcpy((char *)buf, "asdf");
    size_t buflen = strlen((char *)buf);
    assert_int_equal(enqueue(p->c2s, buf, buflen+1),TPX_SUCCESS);
    p->c2s->write_idx = buflen;
    will_return(__wrap_send, -1);
    will_return(__wrap_send, EINVAL);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, NULL, 0, 5),TPX_CLOSED);
}

static void test_handle_proxy_read_ready_s(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // EPOLLIN
    // Successful
    will_return(__wrap_read, 16384);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EAGAIN);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_WRITE);

    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_SUCCESS);

    // failed
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EINVAL);
    
    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_CLOSED);
}

static void test_handle_proxy_read_ready_c(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // EPOLLIN
    // Successful
    will_return(__wrap_SSL_read, 5);
    will_return(__wrap_SSL_read, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);
    will_return(__wrap_send, 5);

    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 1, 5),TPX_SUCCESS);

    // failed
    will_return(__wrap_SSL_read, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_SYSCALL);
    
    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 1, 5),TPX_CLOSED);
}

static void test_handle_proxy_disconnected(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_SERVER_DISCONNECTED;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_CLOSED);
}

static void test_handle_proxy_bad_state(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = 420;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_FAILURE);
}

static void test_handle_proxy_read_bad_peek(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    // Need a successful read first to fill up the buffer partly
    will_return(__wrap_read, 5);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EAGAIN);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_WRITE);

    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_SUCCESS);

    will_return(__wrap_queue_peek_last, TPX_FAILURE);

    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_CLOSED);

    p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    will_return(__wrap_read, 5);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EAGAIN);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_WRITE);

    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_SUCCESS);

    will_return(__wrap_queue_peek_last, TPX_EMPTY);

    p->state = PS_READY;
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, NULL, 0, 5),TPX_CLOSED);    
}

static void test_empty_outbuf(void **state) {
    proxy_t *p = malloc(sizeof(proxy_t));
    p->state = PS_READY;
    p->ssl = (SSL *)0x0;
    p->s2c = queue_new();
    p->c2s = queue_new();
    p->serv_fd = -1;
    p->client_fd = -1;

    enqueue(p->s2c,NULL,0);
    enqueue(p->c2s,NULL,0);

    assert_int_equal(outbuf_empty(p, 0),1);
    assert_int_equal(outbuf_empty(p, 1),1);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_proxy),
        cmocka_unit_test(test_create_proxy_again),
        cmocka_unit_test(test_create_proxy_connerr),
        cmocka_unit_test(test_create_proxy_bad_malloc),
        cmocka_unit_test(test_create_conn_bad_sock),
        cmocka_unit_test(test_create_conn_fcntl1),
        cmocka_unit_test(test_create_conn_fcntl2),
        cmocka_unit_test(test_pa2e_success),
        cmocka_unit_test(test_pa2e_fail1),
        cmocka_unit_test(test_pa2e_fail2),
        cmocka_unit_test(test_proxy_close_ssl),
        cmocka_unit_test(test_proxy_close_again),
        cmocka_unit_test(test_proxy_close_shutdown_done),
        cmocka_unit_test(test_proxy_close_nossl),
        cmocka_unit_test(test_proxy_close_epoll),
        cmocka_unit_test(test_handle_proxy_cc),
        cmocka_unit_test(test_handle_proxy_sc),
        cmocka_unit_test(test_handle_proxy_ready_s),
        cmocka_unit_test(test_handle_proxy_ready_c),
        cmocka_unit_test(test_handle_proxy_sslerr),
        cmocka_unit_test(test_handle_proxy_senderr),
        cmocka_unit_test(test_handle_proxy_read_ready_s),
        cmocka_unit_test(test_handle_proxy_read_ready_c),
        cmocka_unit_test(test_handle_proxy_disconnected),
        cmocka_unit_test(test_handle_proxy_bad_state),
        cmocka_unit_test(test_handle_proxy_read_bad_peek),
        cmocka_unit_test(test_empty_outbuf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
