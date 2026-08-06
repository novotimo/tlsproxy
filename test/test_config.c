#include "config.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "errors.h"
#include "shmem.h"


// Needed for libcyaml to work
static const cyaml_config_t cyaml_config = {
    .log_fn = cyaml_log,
    .mem_fn = cyaml_mem,
    .log_level = CYAML_LOG_ERROR,
};

// Empty config (means cacerts and cert chain are both null)
static tpx_config_t emptyconf;


/* ------------------------------------------------------------------ *
 * Fixtures
 *
 * Two helpers rather than one, because a fixture rejected by libcyaml and a
 * fixture rejected by tpx_validate_conf are different claims, and folding a
 * parse error into TPX_FAILURE is what let badconf10 and badconf11 sit for
 * months testing a missing listen-port while their comments claimed they
 * tested certificates.
 * ------------------------------------------------------------------ */

static cyaml_err_t loadconf_f(tpx_config_t **config, const char *fname) {
    return(cyaml_load_file(fname, &cyaml_config, &top_schema,
                           (cyaml_data_t **)config, NULL));
}

/** @brief Validate a fixture that is expected to parse. */
static tpx_err_t vfy_f(const char *fname, int *logfd) {
    tpx_config_t *config = NULL;
    cyaml_err_t error = loadconf_f(&config, fname);
    if (error != CYAML_OK)
        fail_msg("%s: libcyaml rejected this (%s), so the validator never ran",
                 fname, cyaml_strerror(error));

    tpx_err_t ret = tpx_validate_conf(config, logfd);
    cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t *)config, 0);
    return ret;
}

/** @brief Parse a fixture and throw the result away, for the cases the schema
 * is supposed to catch on its own. */
static cyaml_err_t parse_f(const char *fname) {
    tpx_config_t *config = NULL;
    cyaml_err_t error = loadconf_f(&config, fname);
    if (error == CYAML_OK)
        cyaml_free(&cyaml_config, &top_schema, (cyaml_data_t *)config, 0);
    return error;
}


/* ------------------------------------------------------------------ *
 * The two destinations
 *
 * A NULL logfd means stderr and a non-NULL one means the master's log, so
 * every claim about one of them has to watch the other as well. Otherwise
 * "it went to the log" is satisfied by a message that went to both.
 * ------------------------------------------------------------------ */

#define CAPBUF 4096

static int stderr_pipe[2] = {-1, -1};
static int stderr_saved = -1;
static int log_pipe[2] = {-1, -1};

static void capture_stderr(void) {
    assert_int_equal(pipe(stderr_pipe), 0);
    stderr_saved = dup(STDERR_FILENO);
    assert_true(stderr_saved >= 0);
    assert_true(dup2(stderr_pipe[1], STDERR_FILENO) >= 0);
    // Descriptor 2 is now the only write end, so putting the real stderr
    // back closes it and the read below reaches EOF instead of blocking.
    close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
}

static void release_stderr(char *buf, size_t buflen) {
    fflush(stderr);
    assert_true(dup2(stderr_saved, STDERR_FILENO) >= 0);
    close(stderr_saved);
    stderr_saved = -1;

    ssize_t n = read(stderr_pipe[0], buf, buflen - 1);
    close(stderr_pipe[0]);
    stderr_pipe[0] = -1;
    buf[n > 0 ? (size_t)n : 0] = '\0';
}

static void capture_log(void) {
    assert_int_equal(pipe(log_pipe), 0);
}

static void release_log(char *buf, size_t buflen) {
    close(log_pipe[1]);
    log_pipe[1] = -1;

    ssize_t n = read(log_pipe[0], buf, buflen - 1);
    close(log_pipe[0]);
    log_pipe[0] = -1;
    buf[n > 0 ? (size_t)n : 0] = '\0';
}

/** @brief The logger is process-wide state, so put it back between tests. */
static int reset_logger(void **state) {
    (void)state;
    g_shmem->logger.enabled = 1;
    g_shmem->logger.loglevel = LL_DEBUG;
    return 0;
}


static void a_null_logfd_puts_the_error_on_stderr(void **state) {
    (void)state;
    char err[CAPBUF];

    capture_stderr();
    assert_int_equal(vfy_f(CFG_DIR "/badconf15.yml", NULL), TPX_FAILURE);
    release_stderr(err, sizeof(err));

    assert_non_null(strstr(err, "Config error in listener https"));
    assert_non_null(strstr(err, "'target-port'"));
}

static void a_logfd_puts_the_error_in_the_log_and_not_on_stderr(void **state) {
    (void)state;
    char err[CAPBUF], log[CAPBUF];

    capture_log();
    capture_stderr();
    assert_int_equal(vfy_f(CFG_DIR "/badconf15.yml", &log_pipe[1]),
                     TPX_FAILURE);
    release_stderr(err, sizeof(err));
    release_log(log, sizeof(log));

    assert_non_null(strstr(log, "event=system_error"));
    assert_non_null(strstr(log, "'target-port'"));
    assert_string_equal(err, "");
}

static void a_listener_error_names_the_listener(void **state) {
    (void)state;
    char log[CAPBUF];

    capture_log();
    assert_int_equal(vfy_f(CFG_DIR "/badconf10.yml", &log_pipe[1]),
                     TPX_FAILURE);
    release_log(log, sizeof(log));

    // The listener in badconf10 is named "", which is the interesting case:
    // the prefix has to be there whether or not the name carries anything.
    assert_non_null(strstr(log, "error_msg=\"Config error in listener \""));
}

static void a_top_level_error_is_not_blamed_on_a_listener(void **state) {
    (void)state;
    char log[CAPBUF];

    capture_log();
    assert_int_equal(vfy_f(CFG_DIR "/badconf13.yml", &log_pipe[1]),
                     TPX_FAILURE);
    release_log(log, sizeof(log));

    assert_non_null(strstr(log, "error_msg=\"Config error\""));
    assert_non_null(strstr(log, "'nworkers'"));
}

/* This pins current behaviour rather than desired behaviour: handle_reload()
 * always has a logfd to pass, so a master running without a logfile gets no
 * report of a failed reload at all. If a stderr fallback is added, this test
 * is the one that should change. */
static void a_disabled_logger_drops_the_error_entirely(void **state) {
    (void)state;
    char err[CAPBUF], log[CAPBUF];
    g_shmem->logger.enabled = 0;

    capture_log();
    capture_stderr();
    assert_int_equal(vfy_f(CFG_DIR "/badconf15.yml", &log_pipe[1]),
                     TPX_FAILURE);
    release_stderr(err, sizeof(err));
    release_log(log, sizeof(log));

    assert_string_equal(log, "");
    assert_string_equal(err, "");
}


/* ------------------------------------------------------------------ *
 * Rules the whole config has to satisfy
 * ------------------------------------------------------------------ */

static void a_zeroed_config_has_no_listeners_and_is_rejected(void **state) {
    (void)state;
    assert_int_equal(tpx_validate_conf(&emptyconf, NULL), TPX_FAILURE);
}

static void nworkers_of_zero_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf13.yml", NULL), TPX_FAILURE);
}

static void nworkers_above_the_cap_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf14.yml", NULL), TPX_FAILURE);
}


/* ------------------------------------------------------------------ *
 * Rules each listener has to satisfy
 * ------------------------------------------------------------------ */

static void a_listener_with_no_ca_certificates_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf10.yml", NULL), TPX_FAILURE);
}

static void cert_chain_together_with_cacerts_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf4.yml", NULL), TPX_FAILURE);
}

static void cacerts_without_a_servcert_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf11.yml", NULL), TPX_FAILURE);
}

static void target_port_of_zero_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf15.yml", NULL), TPX_FAILURE);
}

static void target_port_above_the_port_range_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf16.yml", NULL), TPX_FAILURE);
}

static void listen_port_above_the_port_range_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf17.yml", NULL), TPX_FAILURE);
}

static void listen_port_of_zero_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf21.yml", NULL), TPX_FAILURE);
}

static void tcp_keepidle_above_int_max_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf18.yml", NULL), TPX_FAILURE);
}

static void tcp_keepintvl_above_int_max_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf19.yml", NULL), TPX_FAILURE);
}

static void tcp_keepcnt_above_int_max_is_rejected(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/badconf20.yml", NULL), TPX_FAILURE);
}


/* ------------------------------------------------------------------ *
 * Rules the schema carries, so that the validator is not credited with
 * rejections libcyaml made on its own
 * ------------------------------------------------------------------ */

static void the_schema_rejects_a_negative_nworkers(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf1.yml"), CYAML_OK);
}

static void the_schema_rejects_an_empty_listener_list(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf2.yml"), CYAML_OK);
}

static void the_schema_rejects_an_unknown_loglevel(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf3.yml"), CYAML_OK);
}

static void the_schema_rejects_a_listener_with_no_name(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf5.yml"), CYAML_OK);
}

static void the_schema_rejects_a_listener_with_no_target_ip(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf6.yml"), CYAML_OK);
}

static void the_schema_rejects_a_listener_with_no_target_port(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf7.yml"), CYAML_OK);
}

static void the_schema_rejects_a_listener_with_no_listen_ip(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf8.yml"), CYAML_OK);
}

static void the_schema_rejects_a_listener_with_no_listen_port(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf9.yml"), CYAML_OK);
}

static void the_schema_rejects_a_listener_with_no_servkey(void **state) {
    (void)state;
    assert_int_not_equal(parse_f(CFG_DIR "/badconf12.yml"), CYAML_OK);
}


/* ------------------------------------------------------------------ *
 * Configurations that have to keep working
 * ------------------------------------------------------------------ */

static void the_example_config_validates(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/goodconf1.yml", NULL), TPX_SUCCESS);
}

static void cacerts_with_a_servcert_validates(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/goodconf2.yml", NULL), TPX_SUCCESS);
}

static void every_listener_in_a_long_list_is_checked(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/goodconf3.yml", NULL), TPX_SUCCESS);
}

static void stray_whitespace_does_not_upset_validation(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/goodconf4.yml", NULL), TPX_SUCCESS);
}

/* The name here is far longer than the buffer tpx_validate_conf_l() builds
 * its prefix in, so this is also the case that would go wrong if that
 * snprintf were ever swapped for something that doesn't bound its write. */
static void nworkers_at_the_cap_and_a_very_long_name_validate(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/goodconf5.yml", NULL), TPX_SUCCESS);
}

/* Both ports sit at their floor of 1 here, so this is also what notices if
 * either bound is ever tightened without the fixtures being brought along. */
static void empty_scalars_validate(void **state) {
    (void)state;
    assert_int_equal(vfy_f(CFG_DIR "/goodconf6.yml", NULL), TPX_SUCCESS);
}


int main(void) {
    g_shmem = mmap(NULL, sizeof(shared_t), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert_non_null(g_shmem);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(a_null_logfd_puts_the_error_on_stderr,
                               reset_logger),
        cmocka_unit_test_setup(
            a_logfd_puts_the_error_in_the_log_and_not_on_stderr, reset_logger),
        cmocka_unit_test_setup(a_listener_error_names_the_listener,
                               reset_logger),
        cmocka_unit_test_setup(a_top_level_error_is_not_blamed_on_a_listener,
                               reset_logger),
        cmocka_unit_test_setup(a_disabled_logger_drops_the_error_entirely,
                               reset_logger),

        cmocka_unit_test_setup(
            a_zeroed_config_has_no_listeners_and_is_rejected, reset_logger),
        cmocka_unit_test_setup(nworkers_of_zero_is_rejected, reset_logger),
        cmocka_unit_test_setup(nworkers_above_the_cap_is_rejected,
                               reset_logger),

        cmocka_unit_test_setup(a_listener_with_no_ca_certificates_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(cert_chain_together_with_cacerts_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(cacerts_without_a_servcert_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(target_port_of_zero_is_rejected, reset_logger),
        cmocka_unit_test_setup(target_port_above_the_port_range_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(listen_port_above_the_port_range_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(listen_port_of_zero_is_rejected, reset_logger),
        cmocka_unit_test_setup(tcp_keepidle_above_int_max_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(tcp_keepintvl_above_int_max_is_rejected,
                               reset_logger),
        cmocka_unit_test_setup(tcp_keepcnt_above_int_max_is_rejected,
                               reset_logger),

        cmocka_unit_test(the_schema_rejects_a_negative_nworkers),
        cmocka_unit_test(the_schema_rejects_an_empty_listener_list),
        cmocka_unit_test(the_schema_rejects_an_unknown_loglevel),
        cmocka_unit_test(the_schema_rejects_a_listener_with_no_name),
        cmocka_unit_test(the_schema_rejects_a_listener_with_no_target_ip),
        cmocka_unit_test(the_schema_rejects_a_listener_with_no_target_port),
        cmocka_unit_test(the_schema_rejects_a_listener_with_no_listen_ip),
        cmocka_unit_test(the_schema_rejects_a_listener_with_no_listen_port),
        cmocka_unit_test(the_schema_rejects_a_listener_with_no_servkey),

        cmocka_unit_test_setup(the_example_config_validates, reset_logger),
        cmocka_unit_test_setup(cacerts_with_a_servcert_validates,
                               reset_logger),
        cmocka_unit_test_setup(every_listener_in_a_long_list_is_checked,
                               reset_logger),
        cmocka_unit_test_setup(stray_whitespace_does_not_upset_validation,
                               reset_logger),
        cmocka_unit_test_setup(
            nworkers_at_the_cap_and_a_very_long_name_validate, reset_logger),
        cmocka_unit_test_setup(empty_scalars_validate, reset_logger),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
