#include "event.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#include "errors.h"
#include "listen.h"
#include "proxy.h"


#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

// Arbitrary
#define EPOLLFD_DUMMY 7


// What each wrapped handler was last called with, so that a test can check the
// dispatcher's side of the contract rather than just its return value.
struct handler_call {
    unsigned int calls;
    const void *ptr;
    int epollfd;
    uint32_t events;
    uint8_t tag;
};

static struct handler_call accept_call;
static struct handler_call proxy_call;
static unsigned int errx_calls;

static int reset_calls(void **state) {
    (void)state;
    memset(&accept_call, 0, sizeof(accept_call));
    memset(&proxy_call, 0, sizeof(proxy_call));
    errx_calls = 0;
    return 0;
}


tpx_err_t __wrap_handle_accept(listen_t *listen, int epollfd);
tpx_err_t __wrap_handle_accept(listen_t *listen, int epollfd) {
    accept_call.calls++;
    accept_call.ptr = listen;
    accept_call.epollfd = epollfd;
    return (tpx_err_t)mock();
}

tpx_err_t __wrap_handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                              uint8_t tag);
tpx_err_t __wrap_handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                              uint8_t tag) {
    proxy_call.calls++;
    proxy_call.ptr = proxy;
    proxy_call.epollfd = epollfd;
    proxy_call.events = events;
    proxy_call.tag = tag;
    return (tpx_err_t)mock();
}

// The real errx would take us down with it, so we intercept it here
// Wrap tests that would call errx() in expect_assert_failure()
void __wrap_errx(int eval, const char *fmt, ...);
void __wrap_errx(int eval, const char *fmt, ...) {
    (void)eval;
    (void)fmt;
    errx_calls++;
    mock_assert(0, "errx() called from dispatch_events()", __FILE__, __LINE__);
    abort();
}


// Used for tag calculations, should be put into event.h
#define TAG_BITS 2
#define TAG_MASK ((uintptr_t)((1u << TAG_BITS) - 1u))

// Align both of these the same way malloc does, as that's how they're
// allocated in production. If we switch allocators, this needs changing
static _Alignas(max_align_t) proxy_t proxy_fixture;
static _Alignas(max_align_t) listen_t listen_fixture;

static proxy_t *make_proxy(uint8_t id) {
    memset(&proxy_fixture, 0, sizeof(proxy_fixture));
    proxy_fixture.event_id = id;
    return &proxy_fixture;
}

static listen_t *make_listener(uint8_t id) {
    memset(&listen_fixture, 0, sizeof(listen_fixture));
    listen_fixture.event_id = id;
    return &listen_fixture;
}

// This copies proxy_add_to_epoll() exactly
static event_t *tag_ptr(void *p, uintptr_t t) {
    // Make sure these pointers are always non-tagged and aligned properly
    assert_int_equal((uintptr_t)p & TAG_MASK, 0);
    return (event_t *)((uintptr_t)p | t);
}


// An unknown event id is bad, a fatal error. 
static void dispatch_rejects_unknown_event_ids(void **state) {
    (void)state;
    static const uint8_t bad_ids[] = { 2, 3, 42, 127, 128, 255 };

    for (size_t i = 0; i < ARRAY_LEN(bad_ids); ++i) {
        for (uintptr_t t = 0; t <= TAG_MASK; ++t) {
            event_t *bad = (event_t *)make_proxy(bad_ids[i]);
            reset_calls(NULL);
            expect_assert_failure(
                dispatch_events(tag_ptr(bad, t), EPOLLFD_DUMMY, (uint32_t)EPOLLIN));
            assert_int_equal(errx_calls, 1);
            assert_int_equal(accept_call.calls, 0);
            assert_int_equal(proxy_call.calls, 0);
        }
    }
}


// Make very sure that dispatch only ever forwards a stripped pointer.
// Any non-stripped pointer could be passed to free() or something else
static void dispatch_forwards_stripped_pointer(void **state) {
    (void)state;

    for (uintptr_t t = 0; t <= TAG_MASK; ++t) {
        proxy_t *p = make_proxy(EV_PROXY);
        reset_calls(NULL);
        will_return(__wrap_handle_proxy, TPX_SUCCESS);
        dispatch_events(tag_ptr(p, t), EPOLLFD_DUMMY, (uint32_t)EPOLLIN);
        assert_int_equal(proxy_call.calls, 1);
        assert_ptr_equal(proxy_call.ptr, p);
    }

    for (uintptr_t t = 0; t <= TAG_MASK; ++t) {
        listen_t *l = make_listener(EV_LISTEN);
        reset_calls(NULL);
        will_return(__wrap_handle_accept, TPX_SUCCESS);
        dispatch_events(tag_ptr(l, t), EPOLLFD_DUMMY, (uint32_t)EPOLLIN);
        assert_int_equal(accept_call.calls, 1);
        assert_ptr_equal(accept_call.ptr, l);
    }
}

static void dispatch_forwards_tag_verbatim(void **state) {
    (void)state;

    for (uintptr_t t = 0; t <= TAG_MASK; ++t) {
        proxy_t *p = make_proxy(EV_PROXY);
        reset_calls(NULL);
        will_return(__wrap_handle_proxy, TPX_SUCCESS);
        dispatch_events(tag_ptr(p, t), EPOLLFD_DUMMY, (uint32_t)EPOLLIN);
        assert_int_equal(proxy_call.calls, 1);
        assert_int_equal(proxy_call.tag, (uint8_t)t);
    }
}

/* The worker loop only adds a proxy to its closed set when dispatch_events()
   returns TPX_CLOSED, and that set is the only thing stopping the second fd of
   a pair from being dispatched onto a proxy_t that handle_proxy() already
   free()d earlier in the same epoll_wait batch. A dispatcher that swallowed,
   remapped or defaulted a return code would turn that into a use-after-free,
   so every code has to come back out byte for byte - including ones neither
   handler documents, since the guard keys off equality with TPX_CLOSED only. */
static void dispatch_preserves_handler_return_codes(void **state) {
    (void)state;
    static const tpx_err_t codes[] = {
        TPX_SUCCESS, TPX_FAILURE, TPX_AGAIN, TPX_CLOSED, TPX_EMPTY, -1, 12345
    };

    for (size_t i = 0; i < ARRAY_LEN(codes); ++i) {
        proxy_t *p = make_proxy(EV_PROXY);
        reset_calls(NULL);
        will_return(__wrap_handle_proxy, codes[i]);
        assert_int_equal(dispatch_events((event_t *)p, EPOLLFD_DUMMY, (uint32_t)EPOLLIN),
                         codes[i]);

        p = make_proxy(EV_PROXY);
        reset_calls(NULL);
        will_return(__wrap_handle_proxy, codes[i]);
        assert_int_equal(dispatch_events(tag_ptr(p, 1), EPOLLFD_DUMMY, (uint32_t)EPOLLIN),
                         codes[i]);

        listen_t *l = make_listener(EV_LISTEN);
        reset_calls(NULL);
        will_return(__wrap_handle_accept, codes[i]);
        assert_int_equal(dispatch_events((event_t *)l, EPOLLFD_DUMMY, (uint32_t)EPOLLIN),
                         codes[i]);
    }
}

/* Both fds of a pair share one proxy_t, and main.c keys its closed set on
   del_tag() of whatever epoll hands back. If the dispatcher and del_tag ever
   disagreed about which bits are tag, closing the connection through one fd
   would fail to suppress the other, and the second event would run against
   freed memory. Same proxy, both registrations, one base pointer. */
static void closed_set_key_is_stable_across_both_fds(void **state) {
    (void)state;

    proxy_t *p = make_proxy(EV_PROXY);

    will_return(__wrap_handle_proxy, TPX_CLOSED);
    assert_int_equal(dispatch_events((event_t *)p, EPOLLFD_DUMMY, (uint32_t)EPOLLIN),
                     TPX_CLOSED);
    const void *server_key = proxy_call.ptr;

    will_return(__wrap_handle_proxy, TPX_CLOSED);
    assert_int_equal(dispatch_events(tag_ptr(p, 1), EPOLLFD_DUMMY, (uint32_t)EPOLLIN),
                     TPX_CLOSED);
    const void *client_key = proxy_call.ptr;

    assert_ptr_equal(server_key, client_key);
    assert_ptr_equal(server_key, p);
}

/* EPOLLET is bit 31, so the events mask genuinely uses the full width of a
   uint32_t. handle_proxy() asserts on it and picks EPOLLIN/EPOLLOUT out of it,
   so any narrowing or sign extension in transit would silently drop edge
   triggering or the error flags and leave connections wedged. */
static void dispatch_preserves_events_mask(void **state) {
    (void)state;
    static const uint32_t masks[] = {
        0u,
        (uint32_t)EPOLLIN,
        (uint32_t)EPOLLOUT,
        (uint32_t)EPOLLET,
        (uint32_t)EPOLLIN | (uint32_t)EPOLLRDHUP | (uint32_t)EPOLLHUP
            | (uint32_t)EPOLLERR,
        0x00008000u, 0x00010000u, 0x0000FFFFu, 0xFFFF0000u,
        0x80000000u, 0xFFFFFFFFu
    };

    for (size_t i = 0; i < ARRAY_LEN(masks); ++i) {
        proxy_t *p = make_proxy(EV_PROXY);
        reset_calls(NULL);
        will_return(__wrap_handle_proxy, TPX_SUCCESS);
        dispatch_events(tag_ptr(p, 1), EPOLLFD_DUMMY, masks[i]);
        assert_int_equal(proxy_call.calls, 1);
        assert_int_equal(proxy_call.events, masks[i]);
    }
}

/* Cheap guard on the other passthrough argument. A negative or very large fd
   is not something epoll would hand us, but the dispatcher has no business
   inspecting or narrowing it, and a signature change that did would show here
   rather than as a mysterious EBADF much further down. */
static void dispatch_preserves_epollfd(void **state) {
    (void)state;
    static const int fds[] = { -1, 0, 3, 1023, INT_MAX };

    for (size_t i = 0; i < ARRAY_LEN(fds); ++i) {
        proxy_t *p = make_proxy(EV_PROXY);
        reset_calls(NULL);
        will_return(__wrap_handle_proxy, TPX_SUCCESS);
        dispatch_events(tag_ptr(p, 1), fds[i], (uint32_t)EPOLLIN);
        assert_int_equal(proxy_call.calls, 1);
        assert_int_equal(proxy_call.epollfd, fds[i]);

        listen_t *l = make_listener(EV_LISTEN);
        reset_calls(NULL);
        will_return(__wrap_handle_accept, TPX_SUCCESS);
        dispatch_events((event_t *)l, fds[i], (uint32_t)EPOLLIN);
        assert_int_equal(accept_call.calls, 1);
        assert_int_equal(accept_call.epollfd, fds[i]);
    }
}

/* If the tag were ever dereferenced rather than stripped, event_id would be
   read from offset 1 instead of offset 0. Lay each fixture out so the byte at
   offset 1 names the *other* event type: a dispatcher that forgot to strip
   would then route to the wrong handler, with a pointer that is also misaligned
   by a byte. Checked both ways round so neither ID can pass by luck. */
static void tag_stripping_prevents_adjacent_byte_read(void **state) {
    (void)state;

    proxy_t *p = make_proxy(EV_PROXY);
    ((unsigned char *)p)[1] = EV_LISTEN;
    will_return(__wrap_handle_proxy, TPX_SUCCESS);
    dispatch_events(tag_ptr(p, 1), 3, (uint32_t)EPOLLIN);
    assert_int_equal(proxy_call.calls, 1);
    assert_int_equal(accept_call.calls, 0);
    assert_ptr_equal(proxy_call.ptr, p);

    reset_calls(NULL);

    listen_t *l = make_listener(EV_LISTEN);
    ((unsigned char *)l)[1] = EV_PROXY;
    will_return(__wrap_handle_accept, TPX_SUCCESS);
    dispatch_events(tag_ptr(l, 1), 3, (uint32_t)EPOLLIN);
    assert_int_equal(accept_call.calls, 1);
    assert_int_equal(proxy_call.calls, 0);
    assert_ptr_equal(accept_call.ptr, l);
}

/* dispatch_events() reads event_id through an event_t*, then casts that same
   address to listen_t* or proxy_t*. That only holds while event_id sits at
   offset 0 of all three structs, and while every one of them is aligned enough
   to leave the low two bits of a pointer free for the tag. Both are invisible
   invariants that a struct reorder, a smaller field or a packed attribute would
   break silently - no compiler warning, just wrong dispatch at runtime. */
static void event_header_layout_invariants(void **state) {
    (void)state;

    assert_int_equal(offsetof(event_t, event_id), 0);
    assert_int_equal(offsetof(proxy_t, event_id), 0);
    assert_int_equal(offsetof(listen_t, event_id), 0);

    assert_int_equal(sizeof(((event_t *)0)->event_id), 1);
    assert_int_equal(sizeof(((proxy_t *)0)->event_id), 1);
    assert_int_equal(sizeof(((listen_t *)0)->event_id), 1);

    /* Both IDs have to survive the round trip through the uint8_t field. */
    assert_int_equal((uint8_t)EV_LISTEN, EV_LISTEN);
    assert_int_equal((uint8_t)EV_PROXY, EV_PROXY);
    assert_int_not_equal((uint8_t)EV_LISTEN, (uint8_t)EV_PROXY);

    /* Two spare bits in every pointer the dispatcher can be handed... */
    assert_true(__alignof__(proxy_t) >= 4);
    assert_true(__alignof__(listen_t) >= 4);

    /* ...and the allocator really does leave them clear, which is the
       assumption the whole tagged-pointer scheme rests on. */
    for (int i = 0; i < 8; ++i) {
        proxy_t *p = malloc(sizeof(proxy_t));
        listen_t *l = malloc(sizeof(listen_t));
        assert_non_null(p);
        assert_non_null(l);
        assert_int_equal((uintptr_t)p & 0x3, 0);
        assert_int_equal((uintptr_t)l & 0x3, 0);
        free(p);
        free(l);
    }
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(dispatch_rejects_unknown_event_ids, reset_calls),
        cmocka_unit_test_setup(dispatch_forwards_stripped_pointer, reset_calls),
        cmocka_unit_test_setup(dispatch_forwards_tag_verbatim, reset_calls),
        cmocka_unit_test_setup(dispatch_preserves_handler_return_codes,
                               reset_calls),
        cmocka_unit_test_setup(closed_set_key_is_stable_across_both_fds,
                               reset_calls),
        cmocka_unit_test_setup(dispatch_preserves_events_mask, reset_calls),
        cmocka_unit_test_setup(dispatch_preserves_epollfd, reset_calls),
        cmocka_unit_test_setup(tag_stripping_prevents_adjacent_byte_read,
                               reset_calls),
        cmocka_unit_test_setup(event_header_layout_invariants, reset_calls),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
