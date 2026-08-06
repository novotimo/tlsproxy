#include "proxy.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "macros.h"
#include "event.h"
#include "listen.h"
#include "logging.h"
#include "shmem.h"


#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

// dispatch_events() hands handle_proxy() the raw pointer tag. Bit 0 is
// is_client; see test_event.c for the dispatcher's half of the contract.
#define TAG_SERVER 0u
#define TAG_CLIENT 1u

// The counter create_proxy()/proxy_close() maintain. app/main.c:child_loop()
// refuses to finish a graceful shutdown until it reaches zero, so it is
// load-bearing.
extern uint32_t nproxies;


// Declare wrapped functions that follow the simplest pattern
#define WRAPPED_FUNCS \
    WRAP_FUN(socket, int, (int domain, int type, int protocol),      \
             (domain, type, protocol))                               \
    WRAP_FUN(SSL_free, void, (SSL *p), (p))            \
    WRAP_FUN(SSL_is_init_finished, int, (const SSL *p), (p))       \
    WRAP_FUN_ERR(connect, int, (int sockfd, const struct sockaddr *addr, \
                                socklen_t addrlen),                      \
                 (sockfd, addr, addrlen)) \
    WRAP_FUN_ERR(send, ssize_t, \
                 (int sockfd, const void *buf, size_t size, int flags), \
                 (sockfd, buf, size, flags))                            \
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

/* Varargs have to be handled by hand, and the obvious version is wrong. This
   file used to do

       va_list args; va_start(args, op);
       __real_fcntl(fd, op, args);

   which hands fcntl the va_list object where it wants an int, so a passed
   through F_SETFL would set flags from a pointer value. It never bit because
   every test here mocks fcntl, but the fallback was broken and anything added
   later that relied on it would have failed in a way that pointed at fcntl
   rather than at the harness. F_GETFL and friends take no third argument at
   all, so the only correct version splits on the op. Same shape as the one in
   test_listen.c; keep the two in step. */
int __real_fcntl(int fd, int op, ...);
int __wrap_fcntl(int fd, int op, ...);
int __wrap_fcntl(int fd, int op, ...) {
    if (has_mock())
        return (int)mock();

    switch (op) {
    case F_GETFL:
    case F_GETFD:
    case F_GETOWN:
        return __real_fcntl(fd, op);
    default: {
        va_list args;
        va_start(args, op);
        int arg = va_arg(args, int);
        va_end(args);
        return __real_fcntl(fd, op, arg);
    }
    }
}


/* malloc is deliberately NOT driven by cmocka's mock queue. will_return()
   allocates its own node, so queueing a malloc mock and then queueing anything
   else makes the second will_return() eat the first mock. Two plain flags are
   immune to call ordering and say what they do. */
static void *malloc_override;
static int malloc_fails_next;

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (malloc_fails_next) {
        malloc_fails_next = 0;
        return NULL;
    }
    if (malloc_override) {
        void *p = malloc_override;
        malloc_override = NULL;
        return p;
    }
    return __real_malloc(size);
}


#define MAX_RECORDED 16

/* Every fd close() is asked to drop. The proxy's whole job is holding two fds
   per connection, so "did the error path close what it opened" is the question
   most worth being able to ask directly. */
static struct {
    unsigned int calls;
    int fds[MAX_RECORDED];
} close_log;

int __real_close(int fd);
int __wrap_close(int fd);
int __wrap_close(int fd) {
    if (close_log.calls < MAX_RECORDED)
        close_log.fds[close_log.calls] = fd;
    close_log.calls++;
    if (has_mock()) {
        int r = (int)mock();
        if (has_mock())
            errno = (int)mock();
        return r;
    }
    return __real_close(fd);
}

static int was_closed(int fd) {
    for (unsigned int i = 0; i < close_log.calls && i < MAX_RECORDED; ++i)
        if (close_log.fds[i] == fd)
            return 1;
    return 0;
}


/* Deliberately NOT forwarded to __real_setsockopt, unlike test_listen.c's
   otherwise identical recorder. Every fd in this file is a number the mocked
   socket() invented, so the real call fails EBADF - which is exactly what
   happened when create_connect() first grew its keepalive block: four
   unmockable syscalls started failing on fd 43 and took every create_proxy()
   test down with them.

   The value is recorded alongside the option because "was setsockopt called"
   is not the contract. What matters is that the configured numbers reached the
   socket, and a recorder that only counted calls would pass just as happily
   with keepintvl and keepcnt transposed. */
static struct {
    unsigned int calls;
    int level[MAX_RECORDED];
    int optname[MAX_RECORDED];
    int value[MAX_RECORDED];
} setsockopt_log;

int __wrap_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len);
int __wrap_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len) {
    (void)fd;
    if (setsockopt_log.calls < MAX_RECORDED) {
        setsockopt_log.level[setsockopt_log.calls] = level;
        setsockopt_log.optname[setsockopt_log.calls] = optname;
        setsockopt_log.value[setsockopt_log.calls] =
            (val && len >= (socklen_t)sizeof(int)) ? *(const int *)val : 0;
    }
    setsockopt_log.calls++;
    if (has_mock())
        return (int)mock();
    return 0;
}

static int opt_set_to(int level, int optname, int value) {
    for (unsigned int i = 0; i < setsockopt_log.calls && i < MAX_RECORDED; ++i)
        if (setsockopt_log.level[i] == level &&
            setsockopt_log.optname[i] == optname &&
            setsockopt_log.value[i] == value)
            return 1;
    return 0;
}


/* SSL_write is recorded rather than only mocked, because the question worth
   asking about the client side is "was the client written to at all", and a
   return-value oracle cannot answer that. Defaults to accepting the whole
   buffer, so a test that does not care about short writes need arm nothing -
   and so an unmocked call never reaches __real_SSL_write with the NULL SSL
   that new_proxy() hands out. */
static struct {
    unsigned int calls;
    int nbytes[MAX_RECORDED];
} ssl_write_log;

/* SSL_shutdown is recorded for the same reason: proxy_close() is a destructor
   now, and "it did not try to shut the session down" is a claim about a call
   that did not happen. Defaults to 1 so an unmocked call cannot reach
   __real_SSL_shutdown with a fake SSL pointer. */
static struct {
    unsigned int calls;
} ssl_shutdown_log;

int __wrap_SSL_shutdown(SSL *ssl);
int __wrap_SSL_shutdown(SSL *ssl) {
    (void)ssl;
    ssl_shutdown_log.calls++;
    if (has_mock())
        return (int)mock();
    return 1;
}

ssize_t __wrap_SSL_write(SSL *ssl, const void *buf, int num);
ssize_t __wrap_SSL_write(SSL *ssl, const void *buf, int num) {
    (void)ssl; (void)buf;
    if (ssl_write_log.calls < MAX_RECORDED)
        ssl_write_log.nbytes[ssl_write_log.calls] = num;
    ssl_write_log.calls++;
    if (has_mock())
        return (ssize_t)mock();
    return num;
}


/* epoll_ctl records the whole registration, not just the return code, because
   the tagged pointer this proxy hands epoll is the input test_event.c decodes.
   Testing only the return value would leave the producer side unverified. */
static struct {
    unsigned int calls;
    int op[MAX_RECORDED];
    int fd[MAX_RECORDED];
    void *ptr[MAX_RECORDED];
    uint32_t events[MAX_RECORDED];
} epoll_log;

int __real_epoll_ctl(int efd, int op, int fd, struct epoll_event *e);
int __wrap_epoll_ctl(int efd, int op, int fd, struct epoll_event *e);
int __wrap_epoll_ctl(int efd, int op, int fd, struct epoll_event *e) {
    (void)efd;
    if (epoll_log.calls < MAX_RECORDED) {
        epoll_log.op[epoll_log.calls] = op;
        epoll_log.fd[epoll_log.calls] = fd;
        epoll_log.ptr[epoll_log.calls] = e ? e->data.ptr : NULL;
        epoll_log.events[epoll_log.calls] = e ? e->events : 0u;
    }
    epoll_log.calls++;
    if (has_mock())
        return (int)mock();
    return 0;
}


/* The real log_proxy() dereferences proxy->client_addr with no NULL check
   (src/logging.c:log_proxy()). Recording the argument instead of forwarding it
   lets a test observe a bad call rather than be killed by it, and is
   behaviourally identical to the real thing while the logger is disabled -
   which it is for the whole suite. */
static struct {
    unsigned int calls;
    const proxy_t *proxies[MAX_RECORDED];
    const char *subevents[MAX_RECORDED];
} log_proxy_log;

void __wrap_log_proxy(loglevel_t level, proxy_t *proxy, const char *subevent,
                      const char *msg, const char *desc);
void __wrap_log_proxy(loglevel_t level, proxy_t *proxy, const char *subevent,
                      const char *msg, const char *desc) {
    (void)level; (void)msg; (void)desc;
    if (log_proxy_log.calls < MAX_RECORDED) {
        log_proxy_log.proxies[log_proxy_log.calls] = proxy;
        log_proxy_log.subevents[log_proxy_log.calls] = subevent;
    }
    log_proxy_log.calls++;
}


/* src/ uses <assert.h>, not cmocka's assert, so a failed invariant would
   SIGABRT - and cmocka only installs handlers for SIGFPE/SIGILL/SIGSEGV/
   SIGBUS/SIGSYS, so the whole binary would die with no report and every later
   test would go unrun. glibc's assert() compiles down to a call to
   __assert_fail(), which the linker can interpose like anything else. Routing
   it into mock_assert() turns a process abort into an ordinary named test
   failure that prints the offending expression. */
static unsigned int assert_fail_calls;
static const char *last_assertion;

void __real___assert_fail(const char *assertion, const char *file,
                          unsigned int line, const char *function);
void __wrap___assert_fail(const char *assertion, const char *file,
                          unsigned int line, const char *function);
void __wrap___assert_fail(const char *assertion, const char *file,
                          unsigned int line, const char *function) {
    assert_fail_calls++;
    last_assertion = assertion;
    // Returns only when the test did not arm expect_assert_failure(), in which
    // case it fails the current test and longjmps out of it.
    mock_assert(0, assertion, file, (int)line);
    __real___assert_fail(assertion, file, line, function);
}


static int reset_recorders(void **state) {
    (void)state;
    memset(&close_log, 0, sizeof(close_log));
    memset(&setsockopt_log, 0, sizeof(setsockopt_log));
    memset(&ssl_write_log, 0, sizeof(ssl_write_log));
    memset(&ssl_shutdown_log, 0, sizeof(ssl_shutdown_log));
    memset(&epoll_log, 0, sizeof(epoll_log));
    memset(&log_proxy_log, 0, sizeof(log_proxy_log));
    assert_fail_calls = 0;
    last_assertion = NULL;
    malloc_override = NULL;
    malloc_fails_next = 0;
    return 0;
}


// create_proxy() reaches through listener->peer_addr to connect, so a listener
// is now a required part of any proxy fixture.
static listen_t listener_fixture;

static listen_t *make_listener(void) {
    struct sockaddr_in peer;
    memset(&listener_fixture, 0, sizeof(listener_fixture));
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(8080);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    listener_fixture.event_id = EV_LISTEN;
    listener_fixture.fd = 3;
    memcpy(&listener_fixture.peer_addr, &peer, sizeof(peer));
    listener_fixture.peer_addrlen = (socklen_t)sizeof(peer);
    return &listener_fixture;
}

/* calloc, not malloc: malloc is wrapped, and a fixture that quietly consumed
   an override would make the test that needs one lie. */
static proxy_t *new_proxy(proxy_state_t state) {
    proxy_t *p = calloc(1, sizeof(*p));
    assert_non_null(p);
    p->event_id = EV_PROXY;
    p->state = state;
    p->listener = make_listener();
    p->c2s = queue_new();
    p->s2c = queue_new();
    assert_non_null(p->c2s);
    assert_non_null(p->s2c);
    p->client_fd = -1;
    p->serv_fd = -1;
    p->ssl = NULL;
    return p;
}

static void free_proxy(proxy_t *p) {
    queue_free(p->c2s);
    queue_free(p->s2c);
    free(p);
}

static unsigned char *chunk(size_t len, const char *fill) {
    unsigned char *b = __real_malloc(len);
    assert_non_null(b);
    memset(b, 0, len);
    if (fill)
        memcpy(b, fill, strlen(fill));
    return b;
}


/* ------------------------------------------------------------------ */
/* create_connect()                                                    */
/* ------------------------------------------------------------------ */

static void create_connect_reports_socket_failure(void **state) {
    (void)state;
    proxy_t p;
    memset(&p, 0, sizeof(p));
    p.listener = make_listener();

    will_return(__wrap_socket, -1);
    assert_int_equal(create_connect(&p, 60, 10, 3), -1);
    assert_int_equal(close_log.calls, 0);
}

/* socket() has already succeeded by the time either fcntl() runs, so bailing
   out without close() strands a descriptor for the life of the worker. The
   worker is long-lived and one fd is leaked per failure, so this is a slow
   drift towards EMFILE that no amount of connection churn ever recovers from -
   and once accept() starts failing the listener stops serving entirely. */
static void create_connect_closes_socket_when_getfl_fails(void **state) {
    (void)state;
    proxy_t p;
    memset(&p, 0, sizeof(p));
    p.listener = make_listener();

    will_return(__wrap_socket, 50);
    will_return(__wrap_fcntl, -1);
    assert_int_equal(create_connect(&p, 60, 10, 3), -1);
    assert_true(was_closed(50));
}

static void create_connect_closes_socket_when_setfl_fails(void **state) {
    (void)state;
    proxy_t p;
    memset(&p, 0, sizeof(p));
    p.listener = make_listener();

    will_return(__wrap_socket, 50);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, -1);
    assert_int_equal(create_connect(&p, 60, 10, 3), -1);
    assert_true(was_closed(50));
}

/* The whole point of the keepalive work: nothing else in this program will
   ever notice a backend that dies without sending FIN, because there is no
   idle timeout anywhere. The claim is therefore not "setsockopt was called"
   but "the configured numbers reached the socket" - keepintvl and keepcnt are
   both small ints on the same level, so transposing them is a live mistake
   that a call-counting test would wave through. */
static void create_connect_configures_keepalive_on_the_backend(void **state) {
    (void)state;
    proxy_t p;
    memset(&p, 0, sizeof(p));
    p.listener = make_listener();

    will_return(__wrap_socket, 50);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);

    assert_int_equal(create_connect(&p, 60, 10, 3), 50);
    assert_true(opt_set_to(SOL_SOCKET, SO_KEEPALIVE, 1));
    assert_true(opt_set_to(IPPROTO_TCP, TCP_KEEPIDLE, 60));
    assert_true(opt_set_to(IPPROTO_TCP, TCP_KEEPINTVL, 10));
    assert_true(opt_set_to(IPPROTO_TCP, TCP_KEEPCNT, 3));
    assert_false(was_closed(50));
}

/* Keepalive tuning is a refinement, not a precondition. A kernel that refuses
   TCP_KEEPIDLE leaves a connection that still works and still has keepalive,
   just on the tcp_keepalive_* sysctl defaults instead. Failing the connection
   would convert a rejected tuning knob into a dropped client, so the socket is
   handed back and only the failure is logged.

   The mock queue is armed for all four options, not just the failing one:
   arming only the second would make the first call consume it and the test
   would be measuring a refused SO_KEEPALIVE while claiming otherwise. */
static void create_connect_survives_a_refused_keepalive_option(void **state) {
    (void)state;
    proxy_t p;
    memset(&p, 0, sizeof(p));
    p.listener = make_listener();

    will_return(__wrap_socket, 50);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_setsockopt, 0);      // SO_KEEPALIVE
    will_return(__wrap_setsockopt, -1);     // TCP_KEEPIDLE refused
    will_return(__wrap_setsockopt, 0);      // TCP_KEEPINTVL
    will_return(__wrap_setsockopt, 0);      // TCP_KEEPCNT

    assert_int_equal(create_connect(&p, 60, 10, 3), 50);
    assert_false(was_closed(50));
}


/* ------------------------------------------------------------------ */
/* create_proxy()                                                      */
/* ------------------------------------------------------------------ */

static void create_proxy_ready_when_connect_completes(void **state) {
    (void)state;
    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, 0);

    proxy_t *p = create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000);
    assert_non_null(p);
    assert_int_equal(p->event_id, EV_PROXY);
    assert_non_null(p->c2s);
    assert_non_null(p->s2c);
    assert_int_equal(p->client_fd, 42);
    assert_int_equal(p->serv_fd, 43);
    assert_int_equal(p->state, PS_READY);
    assert_int_equal(p->timer_set, 0);
    assert_int_equal(p->hand_shaken, 0);

    free_proxy(p);
    nproxies--;
}

static void create_proxy_pending_when_connect_blocks(void **state) {
    (void)state;
    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINPROGRESS);
    will_return(__wrap_ngx_rbtree_insert, NULL);

    proxy_t *p = create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000);
    assert_non_null(p);
    assert_int_equal(p->state, PS_SERVER_CONNECTING);
    assert_int_equal(p->timer_set, 1);

    free_proxy(p);
    nproxies--;
}

static void create_proxy_null_when_connect_fails(void **state) {
    (void)state;
    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, ECONNREFUSED);

    assert_null(create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000));
}

static void create_proxy_null_when_malloc_fails(void **state) {
    (void)state;
    malloc_fails_next = 1;
    assert_null(create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000));
    // Nothing was opened, so nothing may be closed or counted.
    assert_int_equal(close_log.calls, 0);
}

/* app/main.c:child_loop() finishes a graceful shutdown only once nproxies hits
   zero, but create_proxy() runs nproxies++ after the failure branch has
   already NULLed the proxy out, so a refused backend permanently inflates the
   count. One failed connection is enough to make SIGTERM never complete: the
   worker sits in its event loop forever and the master waits on it. Under a
   backend outage every accepted connection lands here at once. */
static void create_proxy_failure_does_not_leak_nproxies(void **state) {
    (void)state;
    uint32_t before = nproxies;

    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, ECONNREFUSED);

    assert_null(create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000));
    assert_int_equal(nproxies, before);
}

/* Same tail of the same function: the log_proxy() call sits below the failure
   branch, so it runs with proxy == NULL. src/logging.c:log_proxy() reads
   proxy->client_addr.ss_family with no NULL check, which is a straight
   segfault the moment logging is on at debug level. The suite never caught it
   because main() disables the logger, so the read is skipped - the crash only
   shows up in exactly the configuration an operator turns on to diagnose why
   backends are refusing connections. */
static void create_proxy_failure_does_not_log_null_proxy(void **state) {
    (void)state;
    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, ECONNREFUSED);

    assert_null(create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000));
    for (unsigned int i = 0; i < log_proxy_log.calls && i < MAX_RECORDED; ++i)
        assert_non_null(log_proxy_log.proxies[i]);
}

/* The accepted fd belongs to handle_accept() until a proxy is successfully
   built around it: on failure create_proxy() hands back NULL and the caller
   closes it (src/listen.c:handle_accept(), pinned from the other side by
   test_listen.c:handle_accept_closes_fd_when_create_proxy_fails). So the
   failure branch must close the backend socket it opened itself and must leave
   the client fd strictly alone - closing it here too would make every failed
   connection a double close, and on a busy worker the second close lands on
   whatever descriptor the number has since been recycled to. */
static void
create_proxy_failure_closes_only_the_socket_it_opened(void **state) {
    (void)state;
    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, ECONNREFUSED);

    assert_null(create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000));
    assert_true(was_closed(43));
    assert_false(was_closed(42));
}

/* create_proxy() allocates with malloc() and assigns nine of the eleven
   members. client_addr and client_addrlen are never written by anyone:
   handle_accept() has accept()'s sockaddr in hand and a comment telling itself
   to copy it, then calls create_proxy() without it - the parameter was dropped
   when the connection contexts were merged. Commit
   1d016db turned the calloc() into a malloc() at the same time, so what
   logging.c reads back is whatever the allocator last had there. It gates on
   ss_family != AF_UNSPEC, so roughly 65535 times out of 65536 it formats heap
   residue as a client IP and writes it to the log. */
static void create_proxy_initialises_client_addr(void **state) {
    (void)state;
    static _Alignas(max_align_t) unsigned char backing[sizeof(proxy_t)];
    memset(backing, 0xA5, sizeof(backing));
    malloc_override = backing;

    will_return(__wrap_socket, 43);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, 0);

    proxy_t *p = create_proxy(42, NULL, make_listener(), 5, 60, 10, 3,
                              30000, 5000);
    assert_non_null(p);
    assert_int_equal(p->client_addr.ss_family, AF_UNSPEC);
    assert_int_equal(p->client_addrlen, 0);

    queue_free(p->c2s);
    queue_free(p->s2c);
    nproxies--;
}


/* ------------------------------------------------------------------ */
/* proxy_handle_connect()                                              */
/* ------------------------------------------------------------------ */

/* Measured on this kernel rather than assumed: retrying connect() on a
   non-blocking socket returns 0 once the connection has completed - so the
   success path here is right - but -1/EALREADY while it is still in flight.
   proxy_handle_connect() special-cases only EINPROGRESS, which is what the
   *first* call returns, so a retry that means "still working on it" falls into
   the `errno != EINPROGRESS` branch and is reported as a hard failure.

   Reachable whenever the server fd wakes before the connection resolves -
   EPOLLERR and EPOLLHUP arrive on the same registration as EPOLLOUT, and
   handle_proxy() re-enters this function for any event at all. Rare, and the
   damage is one dropped connection rather than anything worse, but the whole
   TPX_AGAIN design exists to be retried and this is the errno that a retry
   actually produces. getsockopt(fd, SOL_SOCKET, SO_ERROR) collects the result
   without the ambiguity. */
static void connect_retry_reports_ealready_as_pending(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_SERVER_CONNECTING);

    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EALREADY);
    assert_int_equal(proxy_handle_connect(p, 5), TPX_AGAIN);

    free_proxy(p);
}


/* ------------------------------------------------------------------ */
/* proxy_add_to_epoll()                                                */
/* ------------------------------------------------------------------ */

/* The producer half of the contract test_event.c verifies from the consumer
   side: server fd registered bare, client fd registered with bit 0 set, both
   resolving to one proxy_t. Getting these backwards would not fail to compile,
   would not fail to run, and would send the backend TLS records - so it is
   worth pinning the actual bytes handed to epoll rather than the return code.
   The alignment assertion is the precondition that makes tagging legal at all;
   it is checked here because this is where the bit is set. */
static void add_to_epoll_tags_client_registration_only(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->client_fd = 12;
    assert_int_equal((uintptr_t)p & 0x3u, 0);

    will_return(__wrap_epoll_ctl, 0);
    will_return(__wrap_epoll_ctl, 0);
    assert_int_equal(proxy_add_to_epoll(p, 7), TPX_SUCCESS);

    assert_int_equal(epoll_log.calls, 2);
    assert_int_equal(epoll_log.op[0], EPOLL_CTL_ADD);
    assert_int_equal(epoll_log.fd[0], 11);
    assert_ptr_equal(epoll_log.ptr[0], p);

    assert_int_equal(epoll_log.op[1], EPOLL_CTL_ADD);
    assert_int_equal(epoll_log.fd[1], 12);
    assert_int_equal((uintptr_t)epoll_log.ptr[1], (uintptr_t)p | 1u);

    // Both data sockets must be edge triggered; the worker drains in a loop
    // and would spin on a level-triggered fd.
    assert_int_not_equal(epoll_log.events[0] & (uint32_t)EPOLLET, 0);
    assert_int_not_equal(epoll_log.events[1] & (uint32_t)EPOLLET, 0);

    free_proxy(p);
}

/* Half-registered proxies are worse than unregistered ones: the server fd
   would keep delivering events against a proxy_t that handle_accept() is about
   to close. */
static void add_to_epoll_rolls_back_server_registration(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->client_fd = 12;

    will_return(__wrap_epoll_ctl, 0);
    will_return(__wrap_epoll_ctl, -1);
    assert_int_equal(proxy_add_to_epoll(p, 7), TPX_FAILURE);

    assert_int_equal(epoll_log.calls, 3);
    assert_int_equal(epoll_log.op[2], EPOLL_CTL_DEL);
    assert_int_equal(epoll_log.fd[2], 11);

    free_proxy(p);
}

static void add_to_epoll_fails_on_server_registration(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->client_fd = 12;

    will_return(__wrap_epoll_ctl, -1);
    assert_int_equal(proxy_add_to_epoll(p, 7), TPX_FAILURE);
    assert_int_equal(epoll_log.calls, 1);

    free_proxy(p);
}


/* ------------------------------------------------------------------ */
/* proxy_close()                                                       */
/* ------------------------------------------------------------------ */

/* proxy_close() returns void now, so nproxies is what says the release
   happened - and it is the thing worth watching anyway, since
   app/main.c:child_loop() will not finish a graceful shutdown until it
   reaches zero. */
static void close_frees_proxy_with_ssl(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_DISCONNECTED);
    p->ssl = (SSL *)0x7;
    uint32_t before = nproxies;

    will_return(__wrap_SSL_free, NULL);
    proxy_close(p, -1);
    assert_int_equal(nproxies, before - 1);
}

static void close_frees_proxy_without_ssl(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_SERVER_DISCONNECTED);
    uint32_t before = nproxies;

    proxy_close(p, -1);
    assert_int_equal(nproxies, before - 1);
}

/* proxy_close() is a destructor and nothing else: emitting the close_notify
   belongs to handle_proxy()'s shutdown states, which are the only place that
   can flush s2c first and then wait out the peer's reply.

   Re-adding an SSL_shutdown() here is the plausible-looking regression, and it
   is the one that breaks against a pipelining client: by this point the peer's
   close_notify has usually already been consumed, so a second call either
   duplicates work or - if the peer sent anything after its alert - fails with
   "application data after close notify" and poisons the SSL object.

   PS_CLOSE_NOTIFY_SENT specifically, because that is the state where the alert
   demonstrably has already gone out. */
static void close_does_not_shut_the_session_down_itself(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLOSE_NOTIFY_SENT);
    p->ssl = (SSL *)0x7;

    will_return(__wrap_SSL_free, NULL);
    proxy_close(p, -1);
    assert_int_equal(ssl_shutdown_log.calls, 0);
}

/* The linger timer is what bounds a peer that never sends its close_notify
   back. Before there was one, proxy_close() returned TPX_AGAIN in that case
   and kept the proxy alive indefinitely - holding the proxy_t, both
   descriptors and its nproxies slot, which meant one silent peer was enough to
   stop SIGTERM ever completing. Expiry has to release unconditionally. */
static void timeout_releases_the_proxy(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLOSE_NOTIFY_SENT);
    p->ssl = (SSL *)0x7;
    uint32_t before = nproxies;

    will_return(__wrap_SSL_free, NULL);
    proxy_handle_timeout(p, -1);
    assert_int_equal(nproxies, before - 1);
}

static void close_closes_both_fds(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_DISCONNECTED);
    p->serv_fd = 11;
    p->client_fd = 12;

    will_return(__wrap_close, 0);
    will_return(__wrap_close, 0);
    proxy_close(p, 1);

    assert_int_equal(epoll_log.calls, 2);
    assert_int_equal(epoll_log.op[0], EPOLL_CTL_DEL);
    assert_int_equal(epoll_log.op[1], EPOLL_CTL_DEL);
    assert_true(was_closed(11));
    assert_true(was_closed(12));
}

/* epollfd == -1 is handle_accept()'s signal that the sockets never made it
   into epoll. Issuing EPOLL_CTL_DEL against fd -1 would log
   a spurious warning on every rejected connection. */
static void close_skips_epoll_when_never_registered(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_DISCONNECTED);
    p->serv_fd = 11;
    p->client_fd = 12;

    will_return(__wrap_close, 0);
    will_return(__wrap_close, 0);
    proxy_close(p, -1);
    assert_int_equal(epoll_log.calls, 0);
}


/* ------------------------------------------------------------------ */
/* handle_proxy() state machine                                        */
/* ------------------------------------------------------------------ */

static void handle_proxy_retries_pending_connect(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_CONNECTED);

    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, EINPROGRESS);
    will_return(__wrap_ngx_rbtree_insert, NULL);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, TAG_SERVER), TPX_AGAIN);
    assert_int_equal(p->state, PS_SERVER_CONNECTING);

    free_proxy(p);
}

static void handle_proxy_becomes_ready_on_connect(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_CONNECTED);

    will_return(__wrap_connect, 0);
    assert_int_equal(handle_proxy(p, -1, EPOLLPRI, TAG_SERVER), TPX_SUCCESS);
    assert_int_equal(p->state, PS_READY);

    free_proxy(p);
}

static void handle_proxy_closes_on_connect_error(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_CONNECTED);

    will_return(__wrap_connect, -1);
    will_return(__wrap_connect, ECONNREFUSED);
    assert_int_equal(handle_proxy(p, -1, EPOLLOUT, TAG_SERVER), TPX_CLOSED);
}

/* PS_CLIENT_DISCONNECTED now carries two situations that want opposite
   handling, and client_notified_close is what separates them. Without the
   flag the client is *gone* - no close_notify, nothing left to deliver to -
   so once c2s is flushed there is nothing to wait for and the proxy is
   released. This is the terminal reading the state used to have
   unconditionally. */
static void handle_proxy_closes_when_the_client_is_gone(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_DISCONNECTED);
    p->hand_shaken = 1;

    assert_int_equal(handle_proxy(p, -1, EPOLLIN, TAG_CLIENT), TPX_CLOSED);
}

/* With the flag, the client merely half-closed: it will send no more but is
   still reading, and the backend has not answered yet. Releasing here is what
   the earlier revision did, and it delivered nothing. The proxy has to stay
   alive, in this same state, pumping serv_fd -> s2c -> client until the
   backend EOFs - PS_SERVER_DISCONNECTED's body never touches the server fd,
   so advancing the state early loses the response. */
static void handle_proxy_keeps_pumping_after_a_client_half_close(void **st) {
    (void)st;
    proxy_t *p = new_proxy(PS_CLIENT_DISCONNECTED);
    p->hand_shaken = 1;
    p->client_notified_close = 1;

    // Backend has nothing to say yet.
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EAGAIN);

    assert_int_equal(handle_proxy(p, -1, EPOLLIN, TAG_CLIENT), TPX_SUCCESS);
    assert_int_equal(p->state, PS_CLIENT_DISCONNECTED);
    assert_int_equal(close_log.calls, 0);

    free_proxy(p);
}

/* PS_SERVER_DISCONNECTED used to be terminal, so this same call used to return
   TPX_CLOSED. It is a working state now: the backend fd has already been
   closed by the time the state is entered, so a server-tagged event left over
   in the same epoll_wait batch refers to a descriptor that is gone and must be
   dropped rather than acted on. */
static void handle_proxy_ignores_server_events_while_shutting_down(void **st) {
    (void)st;
    proxy_t *p = new_proxy(PS_SERVER_DISCONNECTED);
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, TAG_SERVER), TPX_SUCCESS);
    free_proxy(p);
}

/* TAG_SERVER deliberately: handle_proxy() drops every server-tagged event once
   the shutdown states are reachable, and for one revision it did so above the
   state validation, so a corrupt state arriving on the server fd was accepted
   in silence. Validating in the first switch's default puts the guard above
   that early return, which is the only ordering where both tags reach it. */
static void handle_proxy_rejects_unknown_state(void **state) {
    (void)state;
    proxy_t *p = new_proxy((proxy_state_t)420);
    assert_int_equal(handle_proxy(p, -1, EPOLLIN, TAG_SERVER), TPX_FAILURE);
    free_proxy(p);
}

/* SSL_shutdown() reporting -1/WANT_READ means our close_notify is on the wire
   and the peer's has not come back - the ordinary outcome, and the one the
   whole linger phase exists to wait out. Grouping it with the fatal errors
   tears the proxy down on the spot: no SHUT_WR, no lingering, and a close()
   that sends RST to any client with a request still queued.

   Three SSL_get_error mocks because the state machine crosses two states in
   one call, which is the point: the alert result, then proxy_ignore_read()'s
   own check, then proxy_handle_ssl_failure()'s. Nothing wakes this proxy again
   on its own, so the fallthrough has to reach the lingering read here. */
static void client_flushed_lingers_when_the_peer_has_not_replied(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_CLIENT_FLUSHED);
    p->hand_shaken = 1;
    /* The shutdown ceiling is armed on entry to PS_SERVER_DISCONNECTED, so any
       proxy that has reached PS_CLIENT_FLUSHED has a node in the tree - and
       PS_CLOSE_NOTIFY_SENT only deletes it when timer_set says so. */
    p->timer_set = 1;

    will_return(__wrap_SSL_shutdown, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);
    will_return(__wrap_SSL_read, -1);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);
    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);
    will_return(__wrap_ngx_rbtree_delete, NULL);
    will_return(__wrap_ngx_rbtree_insert, NULL);

    assert_int_equal(handle_proxy(p, -1, EPOLLIN, TAG_CLIENT), TPX_SUCCESS);
    assert_int_equal(p->state, PS_CLOSE_NOTIFY_SENT);

    free_proxy(p);
}

/* The analogue of the dispatch bug test_event.c turned up. dispatch_events()
   masks two bits off the pointer and forwards all of them, so handle_proxy()
   can legitimately be called with tag 2 or 3 the moment anything else claims
   bit 1 - a second flag, or a tag widened for a third event type. Before the
   is_client extraction at the top of handle_proxy() the tag was read as
   `tag & 1` when choosing the connect path and as a raw truthy int when passed
   on as is_client, so tag 2 meant "server" in one line and "client" three
   lines later. That routes plaintext into SSL_write and ciphertext into
   send(). Nothing sets bit 1 today, which is why nothing caught it; this pins
   the normalisation so that whoever widens the tag finds out here instead of
   in production. */
static void handle_proxy_ignores_high_tag_bits(void **state) {
    (void)state;
    for (uint8_t tag = 0; tag <= 3; ++tag) {
        proxy_t *p = new_proxy(PS_SERVER_CONNECTING);
        int is_client = tag & 1;

        if (!is_client) {
            // Server side: must drive the connect, exactly as tag 0 does.
            will_return(__wrap_connect, -1);
            will_return(__wrap_connect, EINPROGRESS);
            assert_int_equal(handle_proxy(p, -1, EPOLLPRI, tag), TPX_AGAIN);
            assert_int_equal(p->state, PS_SERVER_CONNECTING);
        } else {
            // Client side: must fall through to the ready path and touch
            // neither connect() nor the timer tree, exactly as tag 1 does.
            assert_int_equal(handle_proxy(p, -1, EPOLLPRI, tag), TPX_SUCCESS);
            assert_int_equal(p->state, PS_SERVER_CONNECTING);
        }
        free_proxy(p);
    }
}


/* ------------------------------------------------------------------ */
/* proxy_handle_read()                                                 */
/* ------------------------------------------------------------------ */

/* The three entry invariants at the top of proxy_handle_read() have to hold on
   a queue that has never been read into, which is the state every proxy starts
   in. This pins the repair of a misplaced one: `buflen > 0` sat above the
   branch that gives buflen a value, so it was false on every call without
   exception, and since Release defines NDEBUG the abort landed only on
   assertion-enabled builds - the proxy died on the first byte either side sent,
   which is what made Debug unrunnable and the read path untestable. It reads
   `buflen < INT_MAX` now, which is what the surrounding casts to int actually
   depend on.

   The read has to be armed even though the invariants are all checked before
   the loop. serv_fd is a made-up number, and __wrap_read forwards to
   __real_read whenever the mock queue is empty, so an unarmed call reads
   whatever descriptor the process happens to have at that number: closed and
   EBADF on CI, and a blocking pipe or socket under a shell that leaks fds,
   where the suite stops dead here. EOF ends the loop on the first pass and
   leaves the invariants as the only thing the test turns on. */
static void read_entry_invariants_hold_on_a_fresh_queue(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    /* Value/errno pair: WRAP_FUN_ERR consumes an errno after each return
       value, and arming the 0 alone would leave the wrapper taking its errno
       off an empty queue. */
    will_return(__wrap_read, 0);
    will_return(__wrap_read, 0);

    (void)proxy_handle_read(p, 0);
    assert_int_equal(assert_fail_calls, 0);

    free_proxy(p);
}

/* A backend that answers and closes hands over both in one epoll wakeup. The
   read loop takes the body, loops, reads 0, and falls out with nbytes == 0 -
   and the server-EOF branch that follows returns TPX_CLOSED from ABOVE the
   proxy_process_data() call. proxy_process_data() is the only thing that moves
   s2c to the client, so the body just read is never written; handle_proxy()
   then goes straight to proxy_close(), which queue_free()s it.

   EPOLLET makes it unrecoverable rather than merely late. The client fd's
   EPOLLOUT edge fired once at registration, when the queue was empty, and no
   further edge arrives until the socket goes unwritable->writable - so the
   flush after a read is the only path that ever drains s2c.

   Live, and not an edge case: it is every HTTP response delimited by
   connection close. What the client sees is a truncated body, which is one of
   the three things separating this proxy from nginx on the same load
   generator (the other two are the RST from close()ing with unread data still
   queued, and the missing close_notify).

   Asserted on the write itself rather than on read_idx: "the client was never
   written to" is the defect, and a queue index is a symptom of it. */
static void server_eof_still_flushes_what_it_just_read(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->client_fd = 12;
    p->hand_shaken = 1;

    /* Body, then EOF, in one call. Value/errno pairs: the WRAP_FUN_ERR
       wrapper consumes an errno after each return value, and arming only the
       two return values would leave the second call unmocked and reading fd
       11 for real. */
    will_return(__wrap_read, 23);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, 0);

    assert_int_equal(proxy_handle_read(p, 0), TPX_CLOSED);

    assert_int_equal(ssl_write_log.calls, 1);
    assert_int_equal(ssl_write_log.nbytes[0], 23);

    free_proxy(p);
}


/* A read that exactly fills a chunk rotates onto a fresh one and leaves that
   one queued and unwritten, so "the queue holds no chunks" and "the last chunk
   holds no bytes" are different states even though both have write_idx == 0.
   Only the first may allocate. Reading the second as the first appends a chunk
   behind one that was never written into, and the write path takes every chunk
   but the last for full, so the peer gets TPX_NET_BUFSIZE bytes of whatever
   the allocator handed back in front of the data. That is the distinction the
   old -1 sentinel carried and the empty flag carries now.

   Asserted on what reached the peer rather than on write_idx, since the index
   is a symptom and the bytes are the defect. */
static void read_fills_the_chunk_a_rotation_left_behind(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    /* Exactly one chunk, then EAGAIN. Value/errno pairs, since WRAP_FUN_ERR
       consumes an errno after every return value, and an unarmed read would
       go to whatever fd 11 happens to be. */
    will_return(__wrap_read, TPX_NET_BUFSIZE);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EAGAIN);
    assert_int_equal(proxy_handle_read(p, 0), TPX_SUCCESS);

    // The rotation happened, and the full chunk went out on its own.
    assert_int_equal(ssl_write_log.calls, 1);
    assert_int_equal(ssl_write_log.nbytes[0], TPX_NET_BUFSIZE);

    // These five bytes belong in the chunk the rotation left behind.
    will_return(__wrap_read, 5);
    will_return(__wrap_read, 0);
    will_return(__wrap_read, -1);
    will_return(__wrap_read, EAGAIN);
    assert_int_equal(proxy_handle_read(p, 0), TPX_SUCCESS);

    assert_int_equal(ssl_write_log.calls, 2);
    assert_int_equal(ssl_write_log.nbytes[1], 5);

    free_proxy(p);
}


/* ------------------------------------------------------------------ */
/* proxy_handle_write()                                                */
/* ------------------------------------------------------------------ */

/* proxy_handle_read() rotates to a fresh chunk the instant a read exactly
   fills the current one, and sets write_idx = 0 as it does. It then calls
   proxy_process_data(), which calls proxy_handle_write() on that same queue,
   so a last chunk with nothing in it is an ordinary state on the write path
   and a peer sending exactly TPX_NET_BUFSIZE bytes produces it.

   This pins the repair of an entry assert that used to read write_idx > 0,
   with a comment claiming the condition held because write always follows
   read. It is read that broke it. The assert was relaxed to >= 0, and unsigned
   indices made even that vacuous, so it is gone; what is pinned now is the
   code it guarded, which drains the full chunk, peeks the fresh one, computes
   real_buflen = 0 and returns without sending. */
static void write_accepts_a_freshly_rotated_chunk(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    assert_int_equal(enqueue(p->c2s, chunk(TPX_NET_BUFSIZE, "payload"),
                             TPX_NET_BUFSIZE), TPX_SUCCESS);
    assert_int_equal(enqueue(p->c2s, chunk(TPX_NET_BUFSIZE, NULL),
                             TPX_NET_BUFSIZE), TPX_SUCCESS);
    p->c2s->read_idx = 0;
    p->c2s->write_idx = 0;  // rotation just happened, nothing in the new chunk

    /* Armed rather than left to the wrapper's fallthrough: this is the server
       side, so an unarmed send() is a real sendto() on whatever fd 11 is, and
       under a shell that leaks a socket there the full chunk goes down it. */
    will_return(__wrap_send, TPX_NET_BUFSIZE);
    will_return(__wrap_send, 0);

    assert_int_equal(proxy_handle_write(p, 0), TPX_SUCCESS);
    assert_int_equal(assert_fail_calls, 0);

    free_proxy(p);
}

/* queue_peek() has three outcomes, and proxy_handle_write() used to branch on
   two: TPX_FAILURE, and `case TPX_SUCCESS: default:`, which folded TPX_EMPTY
   into the success path. wbuf was then whatever it held before, so the first
   iteration asserted on NULL and any later one walked the pointer the previous
   iteration had just free()d. TPX_EMPTY is its own corruption case now, the
   way proxy_handle_read() has always treated it for queue_peek_last().

   Never reachable through the front door: outbuf_empty() rejects an
   already-empty queue on the way in, and the only dequeue in the loop runs
   when first != last, so it always leaves an element behind. Forced with a
   mock for that reason. What it pins is that the third outcome of a
   three-valued API is still handled once the arithmetic holding it off, two
   invariants three functions apart, stops holding. */
static void write_treats_empty_peek_as_corruption(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    assert_int_equal(enqueue(p->c2s, chunk(64, "hello"), 64), TPX_SUCCESS);
    p->c2s->write_idx = 5;

    will_return(__wrap_queue_peek, TPX_EMPTY);
    assert_int_equal(proxy_handle_write(p, 0), TPX_FAILURE);

    free_proxy(p);
}

static void write_reports_corrupt_queue(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    assert_int_equal(enqueue(p->c2s, chunk(64, "hello"), 64), TPX_SUCCESS);
    p->c2s->write_idx = 5;

    will_return(__wrap_queue_peek, TPX_FAILURE);
    assert_int_equal(proxy_handle_write(p, 0), TPX_FAILURE);

    free_proxy(p);
}

static void write_returns_early_on_empty_outbuf(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);

    assert_int_equal(proxy_handle_write(p, 0), TPX_SUCCESS);
    assert_int_equal(proxy_handle_write(p, 1), TPX_SUCCESS);
    assert_int_equal(close_log.calls, 0);

    free_proxy(p);
}

/* A short send() has to leave read_idx pointing at the unsent tail, otherwise
   the remainder is either dropped or retransmitted - and on the client side
   that is TLS record data, so a duplicate is not merely wasteful. EAGAIN after
   a partial write is the normal outcome on a non-blocking socket under load,
   not an edge case. */
static void write_keeps_position_after_short_send(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    assert_int_equal(enqueue(p->c2s, chunk(64, "hello world"), 64),
                     TPX_SUCCESS);
    p->c2s->write_idx = 11;

    will_return(__wrap_send, 4);
    will_return(__wrap_send, 0);
    will_return(__wrap_send, -1);
    will_return(__wrap_send, EAGAIN);
    assert_int_equal(proxy_handle_write(p, 0), TPX_SUCCESS);
    assert_int_equal(p->c2s->read_idx, 4);

    free_proxy(p);
}

static void write_closes_on_server_send_error(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->serv_fd = 11;
    p->hand_shaken = 1;

    assert_int_equal(enqueue(p->c2s, chunk(64, "hello"), 64), TPX_SUCCESS);
    p->c2s->write_idx = 5;

    will_return(__wrap_send, -1);
    will_return(__wrap_send, ECONNRESET);
    assert_int_equal(proxy_handle_write(p, 0), TPX_CLOSED);

    free_proxy(p);
}


/* ------------------------------------------------------------------ */
/* outbuf_empty() and proxy_handle_ssl_failure()                       */
/* ------------------------------------------------------------------ */

static void outbuf_empty_tracks_both_directions(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);

    assert_int_equal(outbuf_empty(p, 0), 1);
    assert_int_equal(outbuf_empty(p, 1), 1);

    assert_int_equal(enqueue(p->c2s, chunk(64, "hello"), 64), TPX_SUCCESS);
    p->c2s->write_idx = 5;
    assert_int_equal(outbuf_empty(p, 0), 0);  // c2s is what is_client=0 sends
    assert_int_equal(outbuf_empty(p, 1), 1);  // s2c is still empty

    // Fully consumed is empty again, even though the chunk is still queued.
    p->c2s->read_idx = 5;
    assert_int_equal(outbuf_empty(p, 0), 1);

    free_proxy(p);
}

/* WANT_READ/WANT_WRITE are the ordinary "call me again" answers from a
   non-blocking SSL object. Treating either as a failure would tear down every
   connection that ever needs a second SSL_read(), so this is the single most
   load-bearing branch in the SSL error mapping. */
static void ssl_failure_treats_want_io_as_success(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->ssl = (SSL *)0x7;

    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_READ);
    assert_int_equal(proxy_handle_ssl_failure(p, -1), TPX_SUCCESS);

    will_return(__wrap_SSL_get_error, SSL_ERROR_WANT_WRITE);
    assert_int_equal(proxy_handle_ssl_failure(p, -1), TPX_SUCCESS);

    free_proxy(p);
}

static void ssl_failure_closes_on_zero_return(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->ssl = (SSL *)0x7;

    will_return(__wrap_SSL_get_error, SSL_ERROR_ZERO_RETURN);
    assert_int_equal(proxy_handle_ssl_failure(p, 0), TPX_CLOSED);
    assert_int_equal(p->hand_shaken, 1);

    free_proxy(p);
}

static void ssl_failure_closes_on_syscall_error(void **state) {
    (void)state;
    proxy_t *p = new_proxy(PS_READY);
    p->ssl = (SSL *)0x7;

    errno = ECONNRESET;
    will_return(__wrap_SSL_get_error, SSL_ERROR_SYSCALL);
    assert_int_equal(proxy_handle_ssl_failure(p, -1), TPX_CLOSED);

    free_proxy(p);
}


int main(void) {
    g_shmem = mmap(NULL, sizeof(shared_t), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert_non_null(g_shmem);
    g_shmem->logger.enabled = 0;

    // So that an unmocked rbtree call lands on a real, initialised tree
    // instead of walking a NULL sentinel.
    proxy_init_timeouts();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(create_connect_reports_socket_failure,
                               reset_recorders),
        cmocka_unit_test_setup(create_connect_closes_socket_when_getfl_fails,
                               reset_recorders),
        cmocka_unit_test_setup(create_connect_closes_socket_when_setfl_fails,
                               reset_recorders),
        cmocka_unit_test_setup(
            create_connect_configures_keepalive_on_the_backend,
            reset_recorders),
        cmocka_unit_test_setup(
            create_connect_survives_a_refused_keepalive_option,
            reset_recorders),

        cmocka_unit_test_setup(create_proxy_ready_when_connect_completes,
                               reset_recorders),
        cmocka_unit_test_setup(create_proxy_pending_when_connect_blocks,
                               reset_recorders),
        cmocka_unit_test_setup(create_proxy_null_when_connect_fails,
                               reset_recorders),
        cmocka_unit_test_setup(create_proxy_null_when_malloc_fails,
                               reset_recorders),
        cmocka_unit_test_setup(create_proxy_failure_does_not_leak_nproxies,
                               reset_recorders),
        cmocka_unit_test_setup(create_proxy_failure_does_not_log_null_proxy,
                               reset_recorders),
        cmocka_unit_test_setup(
            create_proxy_failure_closes_only_the_socket_it_opened,
            reset_recorders),
        cmocka_unit_test_setup(create_proxy_initialises_client_addr,
                               reset_recorders),

        cmocka_unit_test_setup(connect_retry_reports_ealready_as_pending,
                               reset_recorders),

        cmocka_unit_test_setup(add_to_epoll_tags_client_registration_only,
                               reset_recorders),
        cmocka_unit_test_setup(add_to_epoll_rolls_back_server_registration,
                               reset_recorders),
        cmocka_unit_test_setup(add_to_epoll_fails_on_server_registration,
                               reset_recorders),

        cmocka_unit_test_setup(close_frees_proxy_with_ssl, reset_recorders),
        cmocka_unit_test_setup(close_frees_proxy_without_ssl, reset_recorders),
        cmocka_unit_test_setup(close_does_not_shut_the_session_down_itself,
                               reset_recorders),
        cmocka_unit_test_setup(timeout_releases_the_proxy, reset_recorders),
        cmocka_unit_test_setup(close_closes_both_fds, reset_recorders),
        cmocka_unit_test_setup(close_skips_epoll_when_never_registered,
                               reset_recorders),

        cmocka_unit_test_setup(handle_proxy_retries_pending_connect,
                               reset_recorders),
        cmocka_unit_test_setup(handle_proxy_becomes_ready_on_connect,
                               reset_recorders),
        cmocka_unit_test_setup(handle_proxy_closes_on_connect_error,
                               reset_recorders),
        cmocka_unit_test_setup(handle_proxy_closes_when_the_client_is_gone,
                               reset_recorders),
        cmocka_unit_test_setup(
            handle_proxy_keeps_pumping_after_a_client_half_close,
            reset_recorders),
        cmocka_unit_test_setup(
            handle_proxy_ignores_server_events_while_shutting_down,
            reset_recorders),
        cmocka_unit_test_setup(handle_proxy_rejects_unknown_state,
                               reset_recorders),
        cmocka_unit_test_setup(
            client_flushed_lingers_when_the_peer_has_not_replied,
            reset_recorders),
        cmocka_unit_test_setup(handle_proxy_ignores_high_tag_bits,
                               reset_recorders),

        cmocka_unit_test_setup(read_entry_invariants_hold_on_a_fresh_queue,
                               reset_recorders),
        cmocka_unit_test_setup(server_eof_still_flushes_what_it_just_read,
                               reset_recorders),
        cmocka_unit_test_setup(read_fills_the_chunk_a_rotation_left_behind,
                               reset_recorders),

        cmocka_unit_test_setup(write_accepts_a_freshly_rotated_chunk,
                               reset_recorders),
        cmocka_unit_test_setup(write_treats_empty_peek_as_corruption,
                               reset_recorders),
        cmocka_unit_test_setup(write_reports_corrupt_queue, reset_recorders),
        cmocka_unit_test_setup(write_returns_early_on_empty_outbuf,
                               reset_recorders),
        cmocka_unit_test_setup(write_keeps_position_after_short_send,
                               reset_recorders),
        cmocka_unit_test_setup(write_closes_on_server_send_error,
                               reset_recorders),

        cmocka_unit_test_setup(outbuf_empty_tracks_both_directions,
                               reset_recorders),
        cmocka_unit_test_setup(ssl_failure_treats_want_io_as_success,
                               reset_recorders),
        cmocka_unit_test_setup(ssl_failure_closes_on_zero_return,
                               reset_recorders),
        cmocka_unit_test_setup(ssl_failure_closes_on_syscall_error,
                               reset_recorders),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
