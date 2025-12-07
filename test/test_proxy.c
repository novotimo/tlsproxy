#include "proxy.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "event.h"


static void test_create_proxy(void **state) {
    will_return(__wrap_proxy_handle_connect, TPX_SUCCESS);
    struct sockaddr sa;
    proxy_t *p = create_proxy(42, (SSL *)0x47, (struct sockaddr *)&sa,
                              sizeof(struct sockaddr));
    assert_non_null(p);
    assert_int_equal(p->event_id, EV_PROXY);
    assert_non_null(p->c2s);
    assert_non_null(p->s2c);
    assert_int_equal(p->client_fd, 42);
    assert_int_equal(p->serv_fd, 77);
    assert_ptr_equal(p->ssl, 0x47);
    assert_int_equal(p->server_addrlen, sizeof(struct sockaddr));
    proxy_close(p, -1);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_proxy),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
