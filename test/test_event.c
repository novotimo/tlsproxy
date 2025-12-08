#include "event.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include "errors.h"
#include "proxy.h"
#include "listen.h"

#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

static listen_t goodevent1 = {
    .event_id = EV_LISTEN
};

static proxy_t goodevent2 = {
    .event_id = EV_PROXY
};

static event_t badevent1 = {
    .event_id = 3
};

static event_t badevent2 = {
    .event_id = -1
};


/* Make sure we're always getting the right event ID, never a tagged pointer */
tpx_err_t __wrap_handle_accept(listen_t *listen, int epollfd, uint32_t events,
                               void *ssl_ctx) {
    if (!listen)
        return TPX_FAILURE;
    if (((uintptr_t)listen & 0x3) != 0)
        return TPX_FAILURE;
    if (listen->event_id != EV_LISTEN)
        return TPX_FAILURE;
    return TPX_SUCCESS;
}

/* Make sure we're always getting the right event ID, never a tagged pointer */
tpx_err_t __wrap_handle_proxy(proxy_t *proxy, int epollfd, uint32_t events,
                              void *ssl_ctx) {
    if (!proxy)
        return TPX_FAILURE;
    if (((uintptr_t)proxy & 0x3) != 0)
        return TPX_FAILURE;
    if (proxy->event_id != EV_PROXY)
        return TPX_FAILURE;
    return TPX_SUCCESS;
}

void __wrap_errx(int eval, const char *fmt, ...) {
    assert(false);
}


event_t *tag(event_t *ev, uint8_t t) {
    return (event_t *)((uintptr_t) ev + t);
}

/* Make sure we properly test for the configuration rules */
static void test_dispatch_events(void **state) {
    // Test with normal events
    assert_int_equal(dispatch_events((event_t *)&goodevent1, 0, 0, NULL),
                     TPX_SUCCESS);
    assert_int_equal(dispatch_events((event_t *)&goodevent2, 0, 0, NULL),
                     TPX_SUCCESS);

    // Test with tagged events
    assert_int_equal(dispatch_events(tag((event_t *)&goodevent1,2), 0, 0, NULL),
                     TPX_SUCCESS);
    assert_int_equal(dispatch_events(tag((event_t *)&goodevent2,2), 0, 0, NULL),
                     TPX_SUCCESS);

    // Bad events with wrong ID
    expect_assert_failure(dispatch_events((event_t *)&badevent1, 0, 0, NULL));
    expect_assert_failure(dispatch_events((event_t *)&badevent2, 0, 0, NULL));

    // Bad events with tags
    expect_assert_failure(dispatch_events(tag((event_t *)&badevent1,2), 0, 0,
                                          NULL));
    expect_assert_failure(dispatch_events(tag((event_t *)&badevent2,2), 0, 0,
                                          NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dispatch_events),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
