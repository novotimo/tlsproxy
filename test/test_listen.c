#include "listen.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "config.h"
#include "event.h"
#include "logging.h"
#include "macros.h"
#include "proxy.h"
#include "shmem.h"


// create_proxy()/proxy_close() maintain this; the real create_proxy() runs in
// one test below, so the count has to be put back afterwards.
extern uint32_t nproxies;


#define WRAPPED_FUNCS \
    WRAP_FUN(socket, int, (int domain, int type, int protocol), \
             (domain, type, protocol)) \
    WRAP_FUN(listen, int, (int sockfd, int backlog), (sockfd, backlog)) \
    WRAP_FUN_ERR(connect, int, (int sockfd, const struct sockaddr *addr, \
                                socklen_t addrlen), \
                 (sockfd, addr, addrlen)) \
    WRAP_FUN(SSL_new, SSL *, (SSL_CTX *ctx), (ctx)) \
    WRAP_FUN(SSL_free, void, (SSL *ssl), (ssl)) \
    WRAP_FUN(SSL_set_fd, int, (SSL *ssl, int fd), (ssl, fd)) \
    WRAP_FUN(SSL_set_accept_state, void, (SSL *ssl), (ssl))

WRAPPED_FUNCS
#undef WRAP_FUN


/* The old harness did this:

       va_list args; va_start(args, op);
       __real_fcntl(fd, op, args);

   which hands fcntl the va_list object itself where it wants an int, so
   F_SETFL would have set flags from a pointer value. It never bit because
   every test mocked fcntl, but the passthrough path was broken. F_GETFL takes
   no third argument at all, so the only correct version splits on the op. */
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


/* err()/errx() do not return in production - they exit the process. Routing
   them into mock_assert() lets a test say "this input must be fatal" with
   expect_assert_failure() instead of taking the whole binary down. */
void __real_err(int eval, const char *fmt, ...);
void __wrap_err(int eval, const char *fmt, ...);
void __wrap_err(int eval, const char *fmt, ...) {
    (void)eval; (void)fmt;
    mock_assert(0, "err()", __FILE__, __LINE__);
}

void __real_errx(int eval, const char *fmt, ...);
void __wrap_errx(int eval, const char *fmt, ...);
void __wrap_errx(int eval, const char *fmt, ...) {
    (void)eval; (void)fmt;
    mock_assert(0, "errx()", __FILE__, __LINE__);
}


/* Keyed on the hostname rather than queued, because create_listener() resolves
   twice - once in bind_listen_sock() for the local address, once in get_conn()
   for the backend - and a queue cannot say which. Returning a mocked success
   is not an option either: the caller reads *res, which a mock never fills, so
   a queue-driven failure of the first lookup would send bind_listen_sock()
   walking an uninitialised addrinfo list.

   Anything not named here resolves for real. Every host these tests use is a
   numeric literal, which glibc answers without touching the network. */
static const char *getaddrinfo_fails_for;

int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res);
int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res);
int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res) {
    if (getaddrinfo_fails_for != NULL && node != NULL &&
        strcmp(node, getaddrinfo_fails_for) == 0)
        return EAI_NONAME;
    return __real_getaddrinfo(node, service, hints, res);
}


/* Not driven by cmocka's queue, deliberately: will_return() allocates a node
   of its own, so arming a malloc mock and then queueing anything else lets the
   second will_return() eat the first mock. A plain pointer is immune to call
   ordering. Arm it immediately before the call under test, never earlier. */
static void *malloc_override;

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (malloc_override) {
        void *p = malloc_override;
        malloc_override = NULL;
        return p;
    }
    return __real_malloc(size);
}


#define MAX_RECORDED 16

/* handle_accept() owns exactly one resource of its own: the descriptor
   accept() hands back. Nothing above it can clean that up - child_loop() only
   reacts to TPX_CLOSED, and a TPX_FAILURE return carries no fd. So "which fd
   did close() get" is the entire question for this file, and a mock that only
   reports a return code cannot ask it. */
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
    if (has_mock())
        return (int)mock();
    return __real_close(fd);
}

static int was_closed(int fd) {
    for (unsigned int i = 0; i < close_log.calls && i < MAX_RECORDED; ++i)
        if (close_log.fds[i] == fd)
            return 1;
    return 0;
}


/* accept() is the one syscall here whose out-parameter matters, so it cannot
   go through WRAP_FUN - that macro throws arguments away. Filling the sockaddr
   the way the kernel would is what makes it observable whether handle_accept()
   passes the peer address on or drops it. */
static struct sockaddr_storage accept_peer;
static socklen_t accept_peer_len;

int __real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (!has_mock())
        return __real_accept(sockfd, addr, addrlen);

    int fd = (int)mock();
    if (fd >= 0 && addr != NULL && addrlen != NULL) {
        socklen_t n = accept_peer_len < *addrlen ? accept_peer_len : *addrlen;
        memcpy(addr, &accept_peer, n);
        *addrlen = accept_peer_len;
    }
    return fd;
}

static void set_accept_peer(const char *ip, unsigned short port) {
    struct sockaddr_in in;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(port);
    assert_int_equal(inet_pton(AF_INET, ip, &in.sin_addr), 1);
    memset(&accept_peer, 0, sizeof(accept_peer));
    memcpy(&accept_peer, &in, sizeof(in));
    accept_peer_len = (socklen_t)sizeof(in);
}


/* setsockopt is recorded rather than mocked because the defect this file
   catches is in the argument, not the outcome: the call succeeds and still
   sets the wrong option. Passing through keeps the real bind working. */
static struct {
    unsigned int calls;
    int level[MAX_RECORDED];
    int optname[MAX_RECORDED];
} setsockopt_log;

int __real_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len);
int __wrap_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len);
int __wrap_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len) {
    if (setsockopt_log.calls < MAX_RECORDED) {
        setsockopt_log.level[setsockopt_log.calls] = level;
        setsockopt_log.optname[setsockopt_log.calls] = optname;
    }
    setsockopt_log.calls++;
    if (has_mock())
        return (int)mock();
    return __real_setsockopt(fd, level, optname, val, len);
}

static int opt_was_set(int level, int optname) {
    for (unsigned int i = 0; i < setsockopt_log.calls && i < MAX_RECORDED; ++i)
        if (setsockopt_log.level[i] == level &&
            setsockopt_log.optname[i] == optname)
            return 1;
    return 0;
}


/* create_proxy() is recorded AND forwarded on demand. Most tests want a canned
   answer, but the peer-address test needs the real allocator to run so it can
   look at what actually landed in the proxy. has_mock() picks between them. */
/* The six values after the listener are the whole of what connect_conf(),
   keepalive_conf() and shutdown_conf() do, so they are recorded rather than
   discarded: an absent key reaching create_proxy() as 0 is what
   handle_accept_uses_the_default_* below are about, and it is invisible to a
   recorder that only keeps the return value. conn_timeout is uint64_t here
   because that is what inc/proxy.h says; --wrap does not check, so a narrower
   parameter would link and read the low half of the register. */
static struct {
    unsigned int calls;
    int accepted_fd[MAX_RECORDED];
    SSL *ssl[MAX_RECORDED];
    listen_t *listener[MAX_RECORDED];
    uint64_t conn_timeout[MAX_RECORDED];
    int keepidle[MAX_RECORDED];
    int keepintvl[MAX_RECORDED];
    int keepcnt[MAX_RECORDED];
    uint64_t shutdown_timeout[MAX_RECORDED];
    uint64_t shutdown_interval[MAX_RECORDED];
} create_proxy_log;

proxy_t *__real_create_proxy(int accepted_fd, SSL *ssl, listen_t *listener,
                             uint64_t conn_timeout,
                             int keepidle, int keepintvl, int keepcnt,
                             uint64_t shutdown_timeout,
                             uint64_t shutdown_interval);
proxy_t *__wrap_create_proxy(int accepted_fd, SSL *ssl, listen_t *listener,
                             uint64_t conn_timeout,
                             int keepidle, int keepintvl, int keepcnt,
                             uint64_t shutdown_timeout,
                             uint64_t shutdown_interval);
proxy_t *__wrap_create_proxy(int accepted_fd, SSL *ssl, listen_t *listener,
                             uint64_t conn_timeout,
                             int keepidle, int keepintvl, int keepcnt,
                             uint64_t shutdown_timeout,
                             uint64_t shutdown_interval) {
    if (create_proxy_log.calls < MAX_RECORDED) {
        create_proxy_log.accepted_fd[create_proxy_log.calls] = accepted_fd;
        create_proxy_log.ssl[create_proxy_log.calls] = ssl;
        create_proxy_log.listener[create_proxy_log.calls] = listener;
        create_proxy_log.conn_timeout[create_proxy_log.calls] = conn_timeout;
        create_proxy_log.keepidle[create_proxy_log.calls] = keepidle;
        create_proxy_log.keepintvl[create_proxy_log.calls] = keepintvl;
        create_proxy_log.keepcnt[create_proxy_log.calls] = keepcnt;
        create_proxy_log.shutdown_timeout[create_proxy_log.calls] =
            shutdown_timeout;
        create_proxy_log.shutdown_interval[create_proxy_log.calls] =
            shutdown_interval;
    }
    create_proxy_log.calls++;
    if (has_mock())
        return (proxy_t *)mock();
    return __real_create_proxy(accepted_fd, ssl, listener, conn_timeout,
                               keepidle, keepintvl, keepcnt,
                               shutdown_timeout, shutdown_interval);
}


/* proxy_add_to_epoll captures the proxy so a test can inspect what
   handle_accept() built without handle_accept() having to return it. */
static struct {
    unsigned int calls;
    proxy_t *proxy[MAX_RECORDED];
    int epollfd[MAX_RECORDED];
} add_to_epoll_log;

tpx_err_t __wrap_proxy_add_to_epoll(proxy_t *proxy, int epollfd);
tpx_err_t __wrap_proxy_add_to_epoll(proxy_t *proxy, int epollfd) {
    if (add_to_epoll_log.calls < MAX_RECORDED) {
        add_to_epoll_log.proxy[add_to_epoll_log.calls] = proxy;
        add_to_epoll_log.epollfd[add_to_epoll_log.calls] = epollfd;
    }
    add_to_epoll_log.calls++;
    return (tpx_err_t)mock();
}


/* Stubbed, not forwarded: several tests hand create_proxy() a fake non-NULL
   pointer, and the real proxy_close() would dereference it. What handle_accept
   owes the contract is the delegation itself - that it calls proxy_close with
   epollfd = -1 so the sockets are not looked for in an epoll set they never
   reached. test_proxy.c covers what proxy_close() then does. */
static struct {
    unsigned int calls;
    proxy_t *proxy[MAX_RECORDED];
    int epollfd[MAX_RECORDED];
} proxy_close_log;

void __wrap_proxy_close(proxy_t *proxy, int epollfd);
void __wrap_proxy_close(proxy_t *proxy, int epollfd) {
    if (proxy_close_log.calls < MAX_RECORDED) {
        proxy_close_log.proxy[proxy_close_log.calls] = proxy;
        proxy_close_log.epollfd[proxy_close_log.calls] = epollfd;
    }
    proxy_close_log.calls++;
}


/* log_proxy() reads proxy->client_addr.ss_family with no NULL guard
   (src/logging.c:log_proxy()), and create_proxy() calls it with a NULL proxy on
   its own failure path. Recording instead of forwarding keeps that from killing
   the run; with the logger disabled it is behaviourally identical anyway. */
void __wrap_log_proxy(loglevel_t level, proxy_t *proxy, const char *subevent,
                      const char *msg, const char *desc);
void __wrap_log_proxy(loglevel_t level, proxy_t *proxy, const char *subevent,
                      const char *msg, const char *desc) {
    (void)level; (void)proxy; (void)subevent; (void)msg; (void)desc;
}


/* Storage rather than a sentinel address, unlike FAKE_SSL. handle_accept()
   copies accept()'s peer address into proxy->client_addr the moment
   create_proxy() returns, so whatever a stubbed create_proxy() hands back is
   written through before any test gets to look at it - the ((proxy_t *)0x10)
   this used to be segfaulted there. Tests still only compare it by identity. */
static proxy_t proxy_fixture;
#define FAKE_PROXY (&proxy_fixture)

static int reset_recorders(void **state) {
    (void)state;
    memset(&close_log, 0, sizeof(close_log));
    memset(&setsockopt_log, 0, sizeof(setsockopt_log));
    memset(&create_proxy_log, 0, sizeof(create_proxy_log));
    memset(&add_to_epoll_log, 0, sizeof(add_to_epoll_log));
    memset(&proxy_close_log, 0, sizeof(proxy_close_log));
    memset(&proxy_fixture, 0, sizeof(proxy_fixture));
    set_accept_peer("192.0.2.77", 51000);
    malloc_override = NULL;
    getaddrinfo_fails_for = NULL;
    return 0;
}


/* handle_accept() dereferences listen->config->connect_timeout and asserts on
   event_id, so both have to be real. */
static tpx_listen_conf_t conf_fixture;
static listen_t listener_fixture;

#define ACCEPTED_FD 40
#define BACKEND_FD  60
#define FAKE_SSL    ((SSL *)0x20)
// FAKE_PROXY is declared above reset_recorders, which has to clear it.

static listen_t *make_listener(void) {
    memset(&conf_fixture, 0, sizeof(conf_fixture));
    conf_fixture.name = "test";
    conf_fixture.listen_ip = "127.0.0.1";
    conf_fixture.listen_port = 0;
    conf_fixture.target_ip = "127.0.0.1";
    conf_fixture.target_port = 8080;
    conf_fixture.connect_timeout = 5;

    memset(&listener_fixture, 0, sizeof(listener_fixture));
    listener_fixture.event_id = EV_LISTEN;
    listener_fixture.fd = 3;
    listener_fixture.config = &conf_fixture;
    listener_fixture.ssl_ctx = NULL;
    return &listener_fixture;
}

/* Walks handle_accept() as far as the named step, queueing the mocks each
   earlier step consumes. Spelling this out in every test buried the one line
   that differed between them. */
static void accept_up_to_ssl(void) {
    will_return(__wrap_accept, ACCEPTED_FD);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
}


/* ------------------------------------------------------------------ */
/* handle_accept(): who owns the accepted descriptor                   */
/* ------------------------------------------------------------------ */

/* accept() failing is the one early exit with nothing to clean up, so it also
   pins the baseline the leak tests below are measured against: on this path
   close() is genuinely not supposed to be called. */
static void handle_accept_reports_accept_failure(void **state) {
    (void)state;
    will_return(__wrap_accept, -1);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_int_equal(close_log.calls, 0);
    assert_int_equal(create_proxy_log.calls, 0);
}

/* Every early return from here down abandons an open descriptor. Nothing
   upstream recovers it: dispatch_events() just relays the return code, and
   child_loop() only acts on TPX_CLOSED, so a TPX_FAILURE means the fd is gone
   for the life of the worker.

   These first two are the mild ones. F_GETFL and F_SETFL on a descriptor
   accept() returned a microsecond earlier fail for essentially no reason a
   running system produces, so treat them as latent rather than live. They are
   here because they are the same defect as the three below it, they cost one
   line each to fix, and leaving two of five paths uncovered is how the next
   person concludes the pattern was deliberate. */
static void handle_accept_closes_fd_when_getfl_fails(void **state) {
    (void)state;
    will_return(__wrap_accept, ACCEPTED_FD);
    will_return(__wrap_fcntl, -1);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_true(was_closed(ACCEPTED_FD));
}

static void handle_accept_closes_fd_when_setfl_fails(void **state) {
    (void)state;
    will_return(__wrap_accept, ACCEPTED_FD);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, -1);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_true(was_closed(ACCEPTED_FD));
}

/* SSL_new() returns NULL when OpenSSL cannot allocate. That is reachable on a
   box under memory pressure, and memory pressure is exactly when leaking
   descriptors makes things worse. */
static void handle_accept_closes_fd_when_ssl_new_fails(void **state) {
    (void)state;
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, NULL);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_true(was_closed(ACCEPTED_FD));
}

/* SSL_set_fd() returns 0 when the socket BIO cannot be allocated. The code
   does free the SSL object here, which is why this reads as a considered
   cleanup path rather than an oversight - it just cleans up the wrong half.
   SSL_set_fd() installs the fd with BIO_NOCLOSE, so SSL_free() never closes
   it, and on this path the BIO does not exist to begin with. */
static void handle_accept_closes_fd_when_ssl_set_fd_fails(void **state) {
    (void)state;
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 0);
    will_return(__wrap_SSL_free, NULL);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_true(was_closed(ACCEPTED_FD));
}

/* create_proxy() returns NULL whenever connect() to the backend fails outright
   - a refused connection, no route, the backend simply being down - and on
   that path it closes the backend socket it opened but deliberately leaves the
   client fd alone (test_proxy.c:create_proxy_failure_closes_only_the_socket_
   it_opened). Ownership of the accepted fd therefore stays here until a proxy
   exists to take it, and handle_accept() has to close it before returning.

   Left undone this is a descriptor burned per attempt with the backend down,
   until the worker hits EMFILE and accept() starts failing, at which point it
   stops serving the connections it could still have served. */
static void handle_accept_closes_fd_when_create_proxy_fails(void **state) {
    (void)state;
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, NULL);
    will_return(__wrap_SSL_free, NULL);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_int_equal(create_proxy_log.calls, 1);
    assert_true(was_closed(ACCEPTED_FD));
}

/* The other half of the same path, pinned separately so that the close above
   cannot quietly grow into a double free of the SSL object. */
static void handle_accept_frees_ssl_when_create_proxy_fails(void **state) {
    (void)state;
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, NULL);
    will_return(__wrap_SSL_free, NULL);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_ptr_equal(create_proxy_log.ssl[0], FAKE_SSL);
}

/* Once a proxy exists the descriptors belong to it, and the epoll failure path
   correctly hands them back through proxy_close(). The -1 matters: the sockets
   were never registered, so passing a real epollfd would make proxy_close()
   issue EPOLL_CTL_DEL on unregistered fds and log a warning for each. */
static void handle_accept_delegates_cleanup_on_epoll_failure(void **state) {
    (void)state;
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, FAKE_PROXY);
    will_return(__wrap_proxy_add_to_epoll, TPX_FAILURE);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_FAILURE);
    assert_int_equal(proxy_close_log.calls, 1);
    assert_ptr_equal(proxy_close_log.proxy[0], FAKE_PROXY);
    assert_int_equal(proxy_close_log.epollfd[0], -1);
}

/* The happy path, mostly here to prove the failure tests above are failing for
   the reason they claim: same mocks, one outcome changed, nothing closed. */
static void handle_accept_succeeds_and_keeps_the_descriptor(void **state) {
    (void)state;
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, FAKE_PROXY);
    will_return(__wrap_proxy_add_to_epoll, TPX_SUCCESS);

    assert_int_equal(handle_accept(make_listener(), 9), TPX_SUCCESS);
    assert_int_equal(close_log.calls, 0);
    assert_int_equal(proxy_close_log.calls, 0);
    assert_int_equal(create_proxy_log.accepted_fd[0], ACCEPTED_FD);
}


/* ------------------------------------------------------------------ */
/* handle_accept(): the optional keys and their defaults               */
/* ------------------------------------------------------------------ */

/* libcyaml reads an absent optional unsigned as 0, so every one of these
   arrives at handle_accept() indistinguishable from a key written as 0, and
   connect_conf()/keepalive_conf()/shutdown_conf() are what turn it back into
   something usable. Each of them is a value the socket layer cannot take: a
   connect timeout of 0 expires on the next pass through the loop, and
   setsockopt() refuses 0 for all three TCP_KEEP* options with EINVAL. */
static void accept_through_to_create_proxy(void) {
    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    will_return(__wrap_create_proxy, FAKE_PROXY);
    will_return(__wrap_proxy_add_to_epoll, TPX_SUCCESS);
}

static void handle_accept_defaults_an_absent_connect_timeout(void **state) {
    (void)state;
    listen_t *l = make_listener();
    conf_fixture.connect_timeout = 0;

    accept_through_to_create_proxy();
    assert_int_equal(handle_accept(l, 9), TPX_SUCCESS);

    assert_int_equal(create_proxy_log.conn_timeout[0],
                     TPX_DEFAULT_CONNECT_TIMEOUT);
}

/* The other half of the pair: a configured value has to survive, or the test
   above is satisfied by a function that returns the default unconditionally. */
static void handle_accept_passes_a_configured_connect_timeout_through(
        void **state) {
    (void)state;
    listen_t *l = make_listener();
    conf_fixture.connect_timeout = 5;

    accept_through_to_create_proxy();
    assert_int_equal(handle_accept(l, 9), TPX_SUCCESS);

    assert_int_equal(create_proxy_log.conn_timeout[0], 5);
}

static void handle_accept_defaults_absent_keepalives(void **state) {
    (void)state;
    listen_t *l = make_listener();
    conf_fixture.tcp_keepidle = 0;
    conf_fixture.tcp_keepintvl = 0;
    conf_fixture.tcp_keepcnt = 0;

    accept_through_to_create_proxy();
    assert_int_equal(handle_accept(l, 9), TPX_SUCCESS);

    assert_int_equal(create_proxy_log.keepidle[0], TPX_DEFAULT_TCP_KEEPIDLE);
    assert_int_equal(create_proxy_log.keepintvl[0], TPX_DEFAULT_TCP_KEEPINTVL);
    assert_int_equal(create_proxy_log.keepcnt[0], TPX_DEFAULT_TCP_KEEPCNT);
}

static void handle_accept_passes_configured_keepalives_through(void **state) {
    (void)state;
    listen_t *l = make_listener();
    conf_fixture.tcp_keepidle = 11;
    conf_fixture.tcp_keepintvl = 22;
    conf_fixture.tcp_keepcnt = 33;

    accept_through_to_create_proxy();
    assert_int_equal(handle_accept(l, 9), TPX_SUCCESS);

    assert_int_equal(create_proxy_log.keepidle[0], 11);
    assert_int_equal(create_proxy_log.keepintvl[0], 22);
    assert_int_equal(create_proxy_log.keepcnt[0], 33);
}

static void handle_accept_defaults_absent_shutdown_timers(void **state) {
    (void)state;
    listen_t *l = make_listener();
    conf_fixture.shutdown_timeout = 0;
    conf_fixture.shutdown_interval = 0;

    accept_through_to_create_proxy();
    assert_int_equal(handle_accept(l, 9), TPX_SUCCESS);

    assert_int_equal(create_proxy_log.shutdown_timeout[0],
                     TPX_DEFAULT_SHUTDOWN_TIMEOUT);
    assert_int_equal(create_proxy_log.shutdown_interval[0],
                     TPX_DEFAULT_SHUTDOWN_INTERVAL);
}

static void handle_accept_passes_configured_shutdown_timers_through(
        void **state) {
    (void)state;
    listen_t *l = make_listener();
    conf_fixture.shutdown_timeout = 44;
    conf_fixture.shutdown_interval = 7;

    accept_through_to_create_proxy();
    assert_int_equal(handle_accept(l, 9), TPX_SUCCESS);

    assert_int_equal(create_proxy_log.shutdown_timeout[0], 44);
    assert_int_equal(create_proxy_log.shutdown_interval[0], 7);
}


/* ------------------------------------------------------------------ */
/* handle_accept(): the peer address                                   */
/* ------------------------------------------------------------------ */

/* handle_accept() asks accept() for the peer address into a local, and there
   is a comment immediately below it - "Make 100% sure that addr gets copied
   into the proxy ctx rather than just its pointer" - warning about a copy the
   code then never makes. create_proxy() takes no sockaddr parameter, so the
   address is discarded at the end of the function.

   The compiler cannot help here: addr is passed by address to accept(), so it
   counts as used, and no -Wunused fires.

   What reads client_addr afterwards is logging.c, which gates on
   ss_family != AF_UNSPEC. create_proxy() allocates with malloc(), so on
   virtually every connection that field is nonzero heap residue and the log
   line carries an invented client IP. Whether that is live depends on the
   logger being on at DEBUG, which is runtime config, not a build flag.

   This runs the real create_proxy() over poisoned memory so the residue is a
   fixed 0xA5A5 rather than whatever the allocator happened to leave. */
static void handle_accept_passes_peer_address_to_the_proxy(void **state) {
    (void)state;
    set_accept_peer("192.0.2.77", 51000);

    accept_up_to_ssl();
    will_return(__wrap_SSL_new, FAKE_SSL);
    will_return(__wrap_SSL_set_fd, 1);
    will_return(__wrap_SSL_set_accept_state, NULL);
    // No create_proxy mock: the real one runs, and needs a backend socket.
    will_return(__wrap_socket, BACKEND_FD);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_connect, 0);
    will_return(__wrap_proxy_add_to_epoll, TPX_SUCCESS);

    // Armed last: every will_return() above allocates, and the first
    // allocation after this point has to be create_proxy()'s.
    static _Alignas(max_align_t) unsigned char backing[sizeof(proxy_t)];
    memset(backing, 0xA5, sizeof(backing));
    malloc_override = backing;

    assert_int_equal(handle_accept(make_listener(), 9), TPX_SUCCESS);
    assert_int_equal(add_to_epoll_log.calls, 1);

    proxy_t *p = add_to_epoll_log.proxy[0];
    assert_ptr_equal(p, backing);
    assert_int_equal(p->client_fd, ACCEPTED_FD);

    const struct sockaddr_in *in = (const struct sockaddr_in *)&p->client_addr;
    assert_int_equal(p->client_addr.ss_family, AF_INET);
    assert_int_equal(ntohs(in->sin_port), 51000);
    assert_int_equal(p->client_addrlen, sizeof(struct sockaddr_in));

    // backing is static, so the proxy itself must not be freed.
    queue_free(p->c2s);
    queue_free(p->s2c);
    nproxies--;
}


/* ------------------------------------------------------------------ */
/* bind_listen_sock()                                                  */
/* ------------------------------------------------------------------ */

/* One assertion per option, because these were once a single call passing
   SO_REUSEADDR | SO_REUSEPORT. setsockopt()'s third argument is an option
   name, not a flag word: on Linux that OR is 2 | 15, which is 15, which is
   SO_REUSEPORT. It compiled, it returned 0, it set one option and silently
   dropped the other, and it read exactly like every correct
   OR-together-your-flags line in the tree (EPOLLIN | EPOLLOUT | EPOLLET two
   files over) - setsockopt is the odd one out for not taking a mask. Adding
   SO_KEEPALIVE to the same OR later changed nothing at all, which is what
   makes a per-option test worth having rather than one that checks the call
   happened.

   Severity of the original, measured rather than assumed: with a real
   TIME_WAIT set up on a loopback port, a bind with no reuse options fails
   EADDRINUSE, and one with SO_REUSEPORT alone - what the OR actually produced
   - succeeds. So the restart failure you would expect from a missing
   SO_REUSEADDR never showed up, because SO_REUSEPORT covered for it. It was
   latent, not live, and would have gone live the moment anyone dropped
   SO_REUSEPORT. */
static void bind_listen_sock_sets_reuseaddr(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);

    int on = -1;
    socklen_t len = sizeof(on);
    assert_int_equal(getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, &len), 0);

    close(fd);
    assert_true(opt_was_set(SOL_SOCKET, SO_REUSEADDR));
    assert_int_equal(on, 1);
}

/* The half that does work, kept separate so the failure above reads as "one
   option is missing" rather than "reuse is broken". */
static void bind_listen_sock_sets_reuseport(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);

    int on = -1;
    socklen_t len = sizeof(on);
    assert_int_equal(getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, &len), 0);

    close(fd);
    assert_int_equal(on, 1);
}

/* The third option that was folded into that OR, and the one with the most
   riding on it. Linux copies SO_KEEPALIVE and the TCP_KEEP* values from the
   listening socket onto everything accept() returns, so this call is what
   decides whether a client that dies without sending FIN is ever noticed -
   there is no idle timeout anywhere in this program, and an unnoticed dead
   client holds a proxy_t, two descriptors and its slot in nproxies, which
   blocks graceful shutdown.

   The values are read back rather than taken from the recorder: passing the
   arguments in the wrong order still gets all three set, and only the kernel's
   answer distinguishes that from getting it right. */
static void bind_listen_sock_sets_keepalive(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);

    int on = -1, idle = -1, intvl = -1, cnt = -1;
    socklen_t len = sizeof(on);
    assert_int_equal(getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, &len), 0);
    len = sizeof(idle);
    assert_int_equal(getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, &len), 0);
    len = sizeof(intvl);
    assert_int_equal(getsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, &len),
                     0);
    len = sizeof(cnt);
    assert_int_equal(getsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, &len), 0);

    close(fd);
    assert_true(opt_was_set(SOL_SOCKET, SO_KEEPALIVE));
    assert_int_equal(on, 1);
    assert_int_equal(idle, 60);
    assert_int_equal(intvl, 10);
    assert_int_equal(cnt, 3);
}

/* The keepalive tuning calls were err(EXIT_FAILURE) until the config validator
   learned the kernel's bounds, and fatal was the wrong half of that pair.
   bind_listen_sock() runs in the worker, after the master has forked, so
   exiting there turns one refused socket option into every worker dying and
   the master reforking them into the same exit. The socket has to come back
   bound even when the kernel says no.

   Four queued returns because the mock queue applies to setsockopt in call
   order: SO_REUSEADDR, SO_REUSEPORT and SO_KEEPALIVE succeed, TCP_KEEPIDLE
   fails, and the three after it, TCP_KEEPINTVL, TCP_KEEPCNT and TCP_NODELAY,
   go to the real syscall. */
static void bind_listen_sock_survives_a_refused_keepidle(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, -1);

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);
    assert_true(opt_was_set(IPPROTO_TCP, TCP_KEEPIDLE));
    assert_true(opt_was_set(IPPROTO_TCP, TCP_KEEPCNT));

    close(fd);
}

/* SO_KEEPALIVE is the master switch rather than a tuning value, so a refusal
   here costs more than the three above it: the other options are copied on to
   accepted sockets but do nothing without this one, and with no idle timeout
   anywhere, that leaves a client which dies without a FIN holding a proxy_t,
   two descriptors and its slot in nproxies indefinitely. It is a warning
   anyway, on the grounds that a listener with degraded keepalive still serves
   traffic and a worker that exits does not. This is the test to change if that
   trade is ever decided the other way. */
static void bind_listen_sock_survives_a_refused_keepalive(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, 0);
    will_return(__wrap_setsockopt, -1);

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);
    assert_true(opt_was_set(SOL_SOCKET, SO_KEEPALIVE));

    close(fd);
}

/* Set on the listener rather than per accepted socket because Linux copies
   TCP_NODELAY onto everything accept() returns, the same way it copies
   SO_KEEPALIVE and the TCP_KEEP* values, measured on 6.18.41. So this one call
   is what decides whether Nagle is off on every client leg the worker ever
   serves, and reading it back off the listening socket is not quite the claim:
   the value the kernel reports here is the one it will clone.

   What it costs when it is missing, measured rather than assumed: with 1000
   held connections each sending 200 bytes on a shared 33 ms tick, p99 was
   42 ms against nginx's 0.86, because a message small enough for Nagle to
   hold waits for an ACK that the peer has already decided to delay. The
   backend leg is the same argument and lives in create_connect(). */
static void bind_listen_sock_sets_nodelay(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);

    int on = -1;
    socklen_t len = sizeof(on);
    assert_int_equal(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, &len), 0);

    close(fd);
    assert_true(opt_was_set(IPPROTO_TCP, TCP_NODELAY));
    assert_int_equal(on, 1);
}

/* Port 0 rather than a hardcoded port: the old suite bound 47239 and left a
   comment accepting defeat if anything else had it. The kernel will hand out a
   free ephemeral port every time, so there is nothing to lose a race with. */
static void bind_listen_sock_fills_in_the_listen_address(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    int fd = bind_listen_sock(&l, "127.0.0.1", 0, 60, 10, 3);
    assert_int_not_equal(fd, -1);

    assert_int_equal(l.listen_addr.ss_family, AF_INET);
    assert_int_equal(l.listen_addrlen, sizeof(struct sockaddr_in));

    struct sockaddr_storage actual;
    socklen_t actual_len = sizeof(actual);
    assert_int_equal(getsockname(fd, (struct sockaddr *)&actual, &actual_len),
                     0);
    assert_int_equal(actual.ss_family, AF_INET);

    close(fd);
}

/* The lookup is failed by name rather than by feeding in a genuinely bad
   hostname, so this costs no DNS round trip and behaves identically on a
   machine with no resolver. The old suite resolved gentoo.org here. */
static void bind_listen_sock_is_fatal_when_the_host_wont_resolve(void **state) {
    (void)state;
    listen_t l;
    memset(&l, 0, sizeof(l));

    getaddrinfo_fails_for = "no-such-host";
    expect_assert_failure(bind_listen_sock(&l, "no-such-host", 0, 60, 10, 3));
}


/* ------------------------------------------------------------------ */
/* create_listener()                                                   */
/* ------------------------------------------------------------------ */

static void create_listener_builds_a_usable_listener(void **state) {
    (void)state;
    listen_t *l = create_listener(make_listener()->config, NULL);
    assert_non_null(l);

    assert_int_equal(l->event_id, EV_LISTEN);
    assert_int_not_equal(l->fd, -1);
    assert_ptr_equal(l->config, &conf_fixture);
    assert_int_equal(l->peer_addr.ss_family, AF_INET);
    assert_int_equal(l->peer_addrlen, sizeof(struct sockaddr_in));

    close(l->fd);
    free(l);
}

/* Pinning current behaviour, not asserting it is right. listen.h says
   bind_listen_sock "sets it to nonblocking mode"; it does not, and no caller
   does it afterwards either - the only O_NONBLOCK calls in src/ are on
   accepted sockets and on the backend socket.

   I went looking for the hang this normally implies, where epoll reports the
   listener readable and the connection is gone by the time accept() runs, and
   could not produce it: the listener is registered EPOLLIN without EPOLLET
   (app/main.c:start_listeners()), so it is level-triggered, each worker builds
   its own SO_REUSEPORT socket after fork() so no two workers race for one
   accept queue, and an RST on an established connection still leaves it
   collectable. So this is not a live bug today and I am not filing it as one.

   It is a trap, though, and this test is the tripwire. Adding EPOLLET to the
   listener registration is a one-word change that looks consistent with
   proxy.c, and it would turn both this and handle_accept()'s single accept per
   event into real defects at the same time. If someone makes the socket
   nonblocking, this test fails and points at the comment. */
static void create_listener_leaves_the_socket_blocking(void **state) {
    (void)state;
    listen_t *l = create_listener(make_listener()->config, NULL);
    assert_non_null(l);

    int flags = fcntl(l->fd, F_GETFL);
    assert_int_not_equal(flags, -1);
    assert_int_equal(flags & O_NONBLOCK, 0);

    close(l->fd);
    free(l);
}

/* create_listener() is documented to "@return The connection context created
   or NULL if it failed". It never returns NULL - every failure path exits
   through err()/errx(). The doc block also still describes the lhost/lport/
   thost/tport parameters the function stopped taking. Recording the real
   contract here so the header can be corrected against something. */
static void create_listener_is_fatal_when_the_target_wont_resolve(
    void **state) {
    (void)state;
    // The local bind has to succeed for this to reach get_conn() at all, so
    // only the backend name is failed.
    listen_t *fixture = make_listener();
    conf_fixture.target_ip = "no-such-target";
    getaddrinfo_fails_for = "no-such-target";

    expect_assert_failure(create_listener(fixture->config, NULL));
}


/* ------------------------------------------------------------------ */
/* get_conn()                                                          */
/* ------------------------------------------------------------------ */

static void get_conn_resolves_a_numeric_address(void **state) {
    (void)state;
    struct sockaddr_storage ss;
    socklen_t len = 0;
    memset(&ss, 0, sizeof(ss));

    assert_int_equal(get_conn("127.0.0.1", 8080, (struct sockaddr *)&ss, &len),
                     TPX_SUCCESS);
    assert_int_equal(ss.ss_family, AF_INET);
    assert_int_equal(len, sizeof(struct sockaddr_in));

    const struct sockaddr_in *in = (const struct sockaddr_in *)&ss;
    assert_int_equal(ntohs(in->sin_port), 8080);
}

static void get_conn_reports_a_failed_lookup(void **state) {
    (void)state;
    struct sockaddr_storage ss;
    socklen_t len = 0;
    memset(&ss, 0, sizeof(ss));

    getaddrinfo_fails_for = "no-such-host";
    assert_int_equal(get_conn("no-such-host", 80, (struct sockaddr *)&ss, &len),
                     TPX_FAILURE);
}

/* Not a failing test - a demonstration of the trap in get_conn()'s signature.
   It takes struct sockaddr *, which is 16 bytes, and memcpy()s ai_addrlen
   bytes into it, which is 28 for IPv6. The doc block says callers must really
   pass a sockaddr_storage, and every caller today does, but the type does not
   say so and _FORTIFY_SOURCE cannot see through the pointer.

   The old test_proxy.c did exactly the wrong thing here - "struct sockaddr sa;"
   passed to create_proxy - so this is not a hypothetical mistake. */
static void get_conn_writes_more_than_a_sockaddr_holds(void **state) {
    (void)state;
    struct sockaddr_storage ss;
    socklen_t len = 0;
    memset(&ss, 0, sizeof(ss));

    assert_int_equal(get_conn("::1", 443, (struct sockaddr *)&ss, &len),
                     TPX_SUCCESS);
    assert_int_equal(ss.ss_family, AF_INET6);
    assert_true(len > sizeof(struct sockaddr));
}


int main(void) {
    g_shmem = mmap(NULL, sizeof(shared_t), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert_non_null(g_shmem);
    g_shmem->logger.enabled = 0;
    proxy_init_timeouts();

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(handle_accept_reports_accept_failure,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_closes_fd_when_getfl_fails,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_closes_fd_when_setfl_fails,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_closes_fd_when_ssl_new_fails,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_closes_fd_when_ssl_set_fd_fails,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_closes_fd_when_create_proxy_fails,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_frees_ssl_when_create_proxy_fails,
                               reset_recorders),
        cmocka_unit_test_setup(handle_accept_delegates_cleanup_on_epoll_failure,
                               reset_recorders),
        cmocka_unit_test_setup(
            handle_accept_succeeds_and_keeps_the_descriptor, reset_recorders),
        cmocka_unit_test_setup(handle_accept_passes_peer_address_to_the_proxy,
                               reset_recorders),

        cmocka_unit_test_setup(handle_accept_defaults_an_absent_connect_timeout,
                               reset_recorders),
        cmocka_unit_test_setup(
            handle_accept_passes_a_configured_connect_timeout_through,
            reset_recorders),
        cmocka_unit_test_setup(handle_accept_defaults_absent_keepalives,
                               reset_recorders),
        cmocka_unit_test_setup(
            handle_accept_passes_configured_keepalives_through,
            reset_recorders),
        cmocka_unit_test_setup(handle_accept_defaults_absent_shutdown_timers,
                               reset_recorders),
        cmocka_unit_test_setup(
            handle_accept_passes_configured_shutdown_timers_through,
            reset_recorders),

        cmocka_unit_test_setup(bind_listen_sock_sets_reuseaddr,
                               reset_recorders),
        cmocka_unit_test_setup(bind_listen_sock_sets_reuseport,
                               reset_recorders),
        cmocka_unit_test_setup(bind_listen_sock_survives_a_refused_keepidle,
                               reset_recorders),
        cmocka_unit_test_setup(bind_listen_sock_survives_a_refused_keepalive,
                               reset_recorders),
        cmocka_unit_test_setup(bind_listen_sock_sets_keepalive,
                               reset_recorders),
        cmocka_unit_test_setup(bind_listen_sock_sets_nodelay,
                               reset_recorders),
        cmocka_unit_test_setup(bind_listen_sock_fills_in_the_listen_address,
                               reset_recorders),
        cmocka_unit_test_setup(
            bind_listen_sock_is_fatal_when_the_host_wont_resolve,
            reset_recorders),

        cmocka_unit_test_setup(create_listener_builds_a_usable_listener,
                               reset_recorders),
        cmocka_unit_test_setup(create_listener_leaves_the_socket_blocking,
                               reset_recorders),
        cmocka_unit_test_setup(
            create_listener_is_fatal_when_the_target_wont_resolve,
            reset_recorders),

        cmocka_unit_test_setup(get_conn_resolves_a_numeric_address,
                               reset_recorders),
        cmocka_unit_test_setup(get_conn_reports_a_failed_lookup,
                               reset_recorders),
        cmocka_unit_test_setup(get_conn_writes_more_than_a_sockaddr_holds,
                               reset_recorders),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
