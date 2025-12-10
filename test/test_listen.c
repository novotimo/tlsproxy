#include "listen.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include "event.h"
#include "proxy.h"
#include "macros.h"


static listen_t goodevent = {
    .event_id = EV_LISTEN,
    .fd = 7
};


#define WRAPPED_FUNCS \
    WRAP_FUN(create_proxy, proxy_t *, \
             (int accepted_fd, listen_t *listen, SSL *ssl,              \
              struct sockaddr const* server_addr, socklen_t server_addrlen), \
             (accepted_fd, listen, ssl, server_addr, server_addrlen)) \
    WRAP_FUN(proxy_add_to_epoll, tpx_err_t, (proxy_t *proxy, int epollfd), \
             (proxy, epollfd)) \
    WRAP_FUN(proxy_close, void, (proxy_t *proxy,int epollfd), (proxy,epollfd)) \
    WRAP_FUN(accept, int, \
             (int sockfd, struct sockaddr *addr, socklen_t addrlen), \
                 (sockfd, addr, addrlen)) \
    WRAP_FUN(SSL_new, SSL *, (SSL_CTX *ctx), (ctx)) \
    WRAP_FUN(SSL_free, void, (SSL *ssl), (ssl)) \
    WRAP_FUN(SSL_set_accept_state, void, (SSL *ssl), (ssl)) \
    WRAP_FUN(SSL_set_fd, int, (SSL *ssl, int fd), (ssl, fd)) \
    WRAP_FUN(socket, int, (int domain, int type, int protocol), \
             (domain, type, protocol))                          \
    WRAP_FUN(listen, int, (int sockfd, int backlog), (sockfd, backlog)) \
    WRAP_FUN(setsockopt, int, \
             (int s, int l, int o, const void *ov, socklen_t ol),       \
             (s,l,o,ov,ol)) \
    WRAP_FUN(malloc, void *, (const size_t size), (size))
        
WRAPPED_FUNCS
#undef WRAP_FUN

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

void __real_errx(int eval, const char *fmt, ...);
void __wrap_errx(int eval, const char *fmt, ...) {
    mock_assert(false,"errx",__FILE__,__LINE__);
}

void __real_err(int eval, const char *fmt, ...);
void __wrap_err(int eval, const char *fmt, ...) {
    mock_assert(false,"err",__FILE__,__LINE__);
}


/* Show that accept works when given a normal event */
static void test_handle_accept1(void **state) {
    // This will test all of the failure guards in sequence
    will_return(__wrap_accept, -1);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);
}

static void test_handle_accept2(void **state) {
    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, -1);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);
}

static void test_handle_accept3(void **state) {
    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, -1);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);
}

static void test_handle_accept4(void **state) {
    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_SSL_new, NULL);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);

}

static void test_handle_accept5(void **state) {
    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_SSL_new, (SSL *)0x1);
    will_return(__wrap_SSL_set_fd, 0);
    will_return(__wrap_SSL_free, NULL);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);
}

static void test_handle_accept6(void **state) {

    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_SSL_new, (SSL *)0x1);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, NULL);
    will_return(__wrap_SSL_free, NULL);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);
}

static void test_handle_accept7(void **state) {

    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_SSL_new, (SSL *)0x1);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, (proxy_t *)0x1);
    will_return(__wrap_proxy_add_to_epoll, TPX_FAILURE);
    will_return(__wrap_proxy_close, NULL);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_FAILURE);
}

static void test_handle_accept_success(void **state) {
    will_return(__wrap_accept, 4);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_SSL_new, (SSL *)0x1);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, (proxy_t *)0x1);
    will_return(__wrap_proxy_add_to_epoll, TPX_SUCCESS);
    assert_int_equal(handle_accept(&goodevent, -1, 0, NULL, 5), TPX_SUCCESS);
}

static void test_get_conn(void **state) {
    struct sockaddr_storage ss;
    socklen_t len;
    // Bad IP address
    assert_int_equal(get_conn("256.7.2.9", 80, (struct sockaddr *)&ss, &len),
                     TPX_FAILURE);

    // Space in domain
    assert_int_equal(get_conn("This is a terrible domain name!", 80,
                              (struct sockaddr *)&ss, &len),
                     TPX_FAILURE);
    
    assert_int_equal(get_conn("please-nobody-have-this-hostname", 443,
                              (struct sockaddr *)&ss, &len),
                     TPX_FAILURE);
    
    assert_int_equal(get_conn("localhost", 443,
                              (struct sockaddr *)&ss, &len),
                     TPX_SUCCESS);
    
    assert_int_equal(get_conn("gentoo.org", 443,
                              (struct sockaddr *)&ss, &len),
                     TPX_SUCCESS);

    assert_int_equal(get_conn("1.1.1.1", 443,
                              (struct sockaddr *)&ss, &len),
                     TPX_SUCCESS);
}

static void test_bound_listen_sock(void **state) {
    // If someone is actually already bound to this I accept defeat
    int sock = bind_listen_sock("127.0.43.72", 47239);

    // This doesn't happen anyway
    assert_int_not_equal(sock, -1);

    struct sockaddr_storage ss;
    socklen_t sslen;
    assert_return_code(!getsockname(sock, (struct sockaddr *)&ss,&sslen),errno);

    close(sock);
}

static void test_reuseaddr(void **state) {
    // If someone is actually already bound to this I accept defeat
    int sock = bind_listen_sock("127.0.43.73", 47239);

    // This doesn't happen anyway
    assert_int_not_equal(sock, -1);

    int sock2 = bind_listen_sock("127.0.43.73", 47239);

    assert_int_not_equal(sock, sock2);

    close(sock);
    close(sock2);
}

static void test_bind_bad_addr(void **state) {
    expect_assert_failure(bind_listen_sock("256.0.0.0", 2));
    expect_assert_failure(bind_listen_sock("1.1.1.1", 9942));
    expect_assert_failure(bind_listen_sock("i-hope-nobody-has-hostname", 0));
}

static void test_bind_errs(void **state) {
    // If all the socket calls fail we should call errx
    will_return(__wrap_socket, -1);
    expect_assert_failure(bind_listen_sock("127.0.0.1", 9999));

    // If the setsockopt call fails we should call err
    will_return(__wrap_setsockopt, -1);
    expect_assert_failure(bind_listen_sock("127.0.0.1", 9999));

    // If the setsockopt call for IPv6 fails we should call err
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, -1);
    expect_assert_failure(bind_listen_sock("::0", 9999));
}

static void test_create_listener(void **state) {
    // If you don't have IPv6 on your localhost then God help you
    listen_t *listener = create_listener("::0",9876,"1.1.1.1",80);
    assert_non_null(listener);
    assert_int_equal(listener->event_id, EV_LISTEN);
    assert_int_in_range(listener->fd, 3, INT_MAX);
    assert_int_in_range(listener->peer_addrlen, 1, sizeof(struct sockaddr_storage));

    close(listener->fd);
    free(listener);
}

static void test_listener_failure(void **state) {
    will_return(__wrap_listen, -1);
    expect_assert_failure(create_listener("::0",9876,"1.1.1.1",80));

    will_return(__wrap_malloc, NULL);
    expect_assert_failure(create_listener("::0",9876,"1.1.1.1",80));

    // This will make get_conn fail because it's a bad target address
    expect_assert_failure(create_listener("::0",9876,"999.0.0.0",80));
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_handle_accept1),
        cmocka_unit_test(test_handle_accept2),
        cmocka_unit_test(test_handle_accept3),
        cmocka_unit_test(test_handle_accept4),
        cmocka_unit_test(test_handle_accept5),
        cmocka_unit_test(test_handle_accept6),
        cmocka_unit_test(test_handle_accept7),
        cmocka_unit_test(test_handle_accept_success),
        cmocka_unit_test(test_get_conn),
        cmocka_unit_test(test_bound_listen_sock),
        cmocka_unit_test(test_reuseaddr),
        cmocka_unit_test(test_bind_bad_addr),
        cmocka_unit_test(test_bind_errs),
        cmocka_unit_test(test_create_listener),
        cmocka_unit_test(test_listener_failure),
  };

    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    return ret;
}
