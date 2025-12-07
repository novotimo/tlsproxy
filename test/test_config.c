#include "config.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "errors.h"

// Empty config (means cacerts and cert chain are both null)
static tpx_config_t badconf1;

// Defining both cacerts and cert_chain
const char *cacerts[] = {"a", "b"};
static tpx_config_t badconf2 = {
    .cacerts = cacerts,
    .cacerts_count = sizeof(cacerts),
    .cert_chain = "c",
    .servcert = "d",
    .servkey = "e"
};

// Defining certchain and also servcert
static tpx_config_t badconf3 = {
    .cert_chain = "a",
    .servcert = "b",
    .servkey = "c"
};

// Defining cacerts but not servcert
static tpx_config_t badconf4 = {
    .cacerts = cacerts,
    .cacerts_count = sizeof(cacerts),
};

// Using cacerts
static tpx_config_t goodconf1 = {
    .cacerts = cacerts,
    .cacerts_count = sizeof(cacerts),
    .servcert = "a",
    .servkey = "b"
};

// Using cert-chain
static tpx_config_t goodconf2 = {
    .cert_chain = "a",
    .servkey = "b"
};


/* Make sure we properly test for the configuration rules */
static void check_conf_validation(void **state) {
    assert_int_equal(tpx_validate_conf(&badconf1),TPX_FAILURE);
    assert_int_equal(tpx_validate_conf(&badconf2),TPX_FAILURE);
    assert_int_equal(tpx_validate_conf(&badconf3),TPX_FAILURE);
    assert_int_equal(tpx_validate_conf(&badconf4),TPX_FAILURE);
    
    assert_int_equal(tpx_validate_conf(&goodconf1),TPX_SUCCESS);
    assert_int_equal(tpx_validate_conf(&goodconf2),TPX_SUCCESS);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_conf_validation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
