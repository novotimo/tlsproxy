#include "config.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "errors.h"


// Needed for libcyaml to work
static const cyaml_config_t cyaml_config = {
    .log_fn = cyaml_log,
    .mem_fn = cyaml_mem,
    .log_level = CYAML_LOG_WARNING,
};

// Empty config (means cacerts and cert chain are both null)
static tpx_config_t emptyconf;


cyaml_err_t loadconf(tpx_config_t **config, const unsigned char *input,
                      size_t len) {
    return(cyaml_load_data(input, len, &cyaml_config, &top_schema,
                           (cyaml_data_t **)config, NULL));
}

cyaml_err_t loadconf_f(tpx_config_t **config, const char *fname) {
    return(cyaml_load_file(fname, &cyaml_config, &top_schema,
                           (cyaml_data_t **)config, NULL));
}

tpx_err_t vfy(const unsigned char *input, size_t len) {
    tpx_config_t *config;
    cyaml_err_t error = loadconf(&config, input, len);
    
    if (error != CYAML_OK) {
        fprintf(stderr, "got cyaml error (%d): %s\n",
                error, cyaml_strerror(error));
        return TPX_FAILURE;
    }

    tpx_err_t ret = tpx_validate_conf(config);
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t **)config, 0);
    return ret;
}

tpx_err_t vfy_f(const char *fname) {
    tpx_config_t *config;
    cyaml_err_t error = loadconf_f(&config, fname);
    
    if (error != CYAML_OK) {
        fprintf(stderr, "got cyaml error (%d): %s\n",
                error, cyaml_strerror(error));
        return TPX_FAILURE;
    }

    tpx_err_t ret = tpx_validate_conf(config);
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t **)config, 0);
    return ret;
}

/* Make sure we properly test for the configuration rules */
static void check_conf_validation(void **state) {
    assert_int_equal(tpx_validate_conf(&emptyconf),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/goodconf1.yml"),TPX_SUCCESS);
    assert_int_equal(vfy_f(CFG_DIR "/goodconf2.yml"),TPX_SUCCESS);
    assert_int_equal(vfy_f(CFG_DIR "/goodconf3.yml"),TPX_SUCCESS);
    assert_int_equal(vfy_f(CFG_DIR "/goodconf4.yml"),TPX_SUCCESS);
    assert_int_equal(vfy_f(CFG_DIR "/goodconf5.yml"),TPX_SUCCESS);
    assert_int_equal(vfy_f(CFG_DIR "/goodconf6.yml"),TPX_SUCCESS);
    assert_int_equal(vfy_f(CFG_DIR "/badconf1.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf2.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf3.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf4.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf5.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf6.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf7.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf8.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf9.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf10.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf11.yml"),TPX_FAILURE);
    assert_int_equal(vfy_f(CFG_DIR "/badconf12.yml"),TPX_FAILURE);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_conf_validation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
