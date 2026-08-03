/* src/ is compiled with whatever standard GCC defaults to -- C_STANDARD 99 is
   set on the tlsproxy executable, not on the proxy library -- so logging.c
   gets the W* wait macros and localtime_r from _DEFAULT_SOURCE. This file has
   to ask for the same view of libc to match it. */
#define _GNU_SOURCE

#include "logging.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "listen.h"
#include "proxy.h"
#include "shmem.h"


/* ------------------------------------------------------------------ *
 * src/logging.c internals
 *
 * linebuf_t and the TPX_MODE_* constants live in src/logging.c, not in a
 * header, so this is a copy. It is not a private reimplementation: the
 * functions below are the real ones, reached by the linker. If the union in
 * src/logging.c changes, this copy has to change with it, and
 * the_length_prefix_shares_storage_with_the_first_four_bytes is the test that
 * notices when it hasn't.
 * ------------------------------------------------------------------ */

#define LINEBUF_OFFSET ((uint32_t)sizeof(uint32_t))

#define TPX_MODE_NONE     0
#define TPX_MODE_SANITIZE 1
#define TPX_MODE_HEX      2

typedef struct linebuf_s {
    union {
        uint32_t len;
        char buf[TPX_LOG_LINE_MAX+1];
    } u;
} linebuf_t;

int _linebuf_append(linebuf_t *linebuf, const char *str, size_t len, int mode);
int _linebuf_putc(linebuf_t *linebuf, const char c);
int _linebuf_append_kv(linebuf_t *linebuf, const char *key, const char *value,
                       size_t value_len);
int _linebuf_append_ossl(linebuf_t *linebuf);
int _base_schema(linebuf_t *linebuf, int is_master, loglevel_t level,
                 const char *event);
int _sanitize_c(const char c, char **outptr, const char *endptr);
int _hex_c(const char c, char **outptr, const char *endptr);
int _ringbuf_fits(logger_t *logger, uint32_t len);
void _write_linebuf(logger_t *logger, linebuf_t *linebuf);
void _write_linebuf_fd(int logfd, linebuf_t *linebuf);
const char *getstraddr(struct sockaddr *sa, uint16_t *port);
const char *strlevel(loglevel_t level);


/* ------------------------------------------------------------------ *
 * Harness
 * ------------------------------------------------------------------ */

/* write_logs() calls errx() when it is asked to run with logging disabled.
   errx is noreturn, so the wrapper must not return either: mock_assert()
   longjmps out of the test whether or not expect_assert_failure() armed it. */
static unsigned int errx_calls;

void __real_errx(int eval, const char *fmt, ...);
void __wrap_errx(int eval, const char *fmt, ...);
void __wrap_errx(int eval, const char *fmt, ...) {
    (void)eval;
    errx_calls++;
    mock_assert(0, fmt ? fmt : "errx", __FILE__, __LINE__);
    __real_errx(eval, "%s", "unreachable");
}

/* cmocka installs handlers for SIGFPE/ILL/SEGV/BUS/SYS but not SIGABRT, so a
   tripped assert() inside src/ kills the binary outright and every later test
   goes unrun. glibc routes assert() through __assert_fail(), which the linker
   interposes like anything else; routing it into mock_assert() turns a process
   abort into an ordinary named failure that prints the expression. */
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
    mock_assert(0, assertion, file, (int)line);
    __real___assert_fail(assertion, file, line, function);
}


/* The logger lives in a MAP_SHARED page in production and the mutex guarding
   it is process-shared. Faking that with a plain static would make
   two_processes_share_one_ring_buffer meaningless, so the fixture is the real
   arrangement: an anonymous shared mapping, re-made for every test. */
static shared_t *shmem_fixture;
static logger_t *logger;

// The master's side of the pipe. Log lines come back out of logpipe[0].
static int logpipe[2] = {-1, -1};

#define LOGBUF_READ 65536
static char logtext[LOGBUF_READ];


static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    assert_int_not_equal(flags, -1);
    assert_int_not_equal(fcntl(fd, F_SETFL, flags | O_NONBLOCK), -1);
}

static int setup_logger(void **state) {
    (void)state;

    shmem_fixture = mmap(NULL, sizeof(shared_t), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert_ptr_not_equal(shmem_fixture, MAP_FAILED);
    memset(shmem_fixture, 0, sizeof(shared_t));

    g_shmem = shmem_fixture;
    logger = &shmem_fixture->logger;

    pthread_mutexattr_t attrs;
    assert_int_equal(pthread_mutexattr_init(&attrs), 0);
    assert_int_equal(pthread_mutexattr_setpshared(&attrs,
                                                  PTHREAD_PROCESS_SHARED), 0);
    assert_int_equal(pthread_mutex_init(&logger->write_lock, &attrs), 0);
    assert_int_equal(pthread_mutexattr_destroy(&attrs), 0);

    logger->enabled = 1;
    logger->loglevel = LL_DEBUG;
    logger->eventfd = eventfd(0, EFD_NONBLOCK);
    assert_int_not_equal(logger->eventfd, -1);

    assert_int_equal(pipe(logpipe), 0);
    set_nonblocking(logpipe[0]);

    errx_calls = 0;
    assert_fail_calls = 0;
    last_assertion = NULL;
    memset(logtext, 0, sizeof(logtext));
    ERR_clear_error();
    errno = 0;
    return 0;
}

static int teardown_logger(void **state) {
    (void)state;

    if (logpipe[0] != -1) close(logpipe[0]);
    if (logpipe[1] != -1) close(logpipe[1]);
    logpipe[0] = logpipe[1] = -1;

    if (logger && logger->eventfd > 0) close(logger->eventfd);
    if (shmem_fixture) munmap(shmem_fixture, sizeof(shared_t));
    shmem_fixture = NULL;
    logger = NULL;
    g_shmem = NULL;
    return 0;
}

// Everything the master has written so far, NUL-terminated. Zero bytes when
// nothing was written, because the read end is non-blocking.
static size_t read_logs(void) {
    memset(logtext, 0, sizeof(logtext));
    ssize_t n = read(logpipe[0], logtext, sizeof(logtext) - 1);
    if (n < 0) n = 0;
    logtext[n] = '\0';
    return (size_t)n;
}

// How many messages the workers have announced since the last check.
static uint64_t take_event_count(void) {
    uint64_t count = 0;
    if (read(logger->eventfd, &count, sizeof(count)) != sizeof(count))
        return 0;
    return count;
}

/* The master's whole job: learn how many messages are queued, then drain them.
   write_logs() returns how many of those events it actually got out, and
   app/main.c:parent_loop() subtracts that from the count to decide what to
   re-arm the eventfd with, so the return value is part of the contract now and
   not a diagnostic. Returning it here lets every caller below assert on it. */
static uint64_t drain_logger(void) {
    uint64_t count = take_event_count();
    if (!count)
        return 0;
    return write_logs(logpipe[1], logger, count);
}

static void assert_contains(const char *haystack, const char *needle) {
    if (strstr(haystack, needle) == NULL)
        fail_msg("expected to find <%s> in:\n%s", needle, haystack);
}

static void assert_not_contains(const char *haystack, const char *needle) {
    if (strstr(haystack, needle) != NULL)
        fail_msg("did not expect <%s> in:\n%s", needle, haystack);
}

// Run one character through the sanitiser into a fresh, roomy buffer.
static const char *sanitized(char c) {
    static char out[16];
    memset(out, 0, sizeof(out));
    char *cursor = out;
    assert_int_equal(_sanitize_c(c, &cursor, out + sizeof(out)), 0);
    return out;
}

// A framed message of exactly total bytes: the 4-byte length prefix that
// _write_linebuf will overwrite with the real length, then filler.
static void linebuf_fill(linebuf_t *lb, uint32_t total, char fill) {
    assert_true(total > LINEBUF_OFFSET);
    assert_true(total <= TPX_LOG_LINE_MAX);
    memset(lb->u.buf, fill, total);
    lb->u.len = total;
}


/* ------------------------------------------------------------------ *
 * The sanitizer
 *
 * Every value in a log line is written as key="value". The sanitizer is the
 * only thing standing between a value and the structure of the line around
 * it, so each of these tests is a claim about what a value cannot do.
 * ------------------------------------------------------------------ */

static void sanitize_escapes_a_newline(void **state) {
    (void)state;
    assert_string_equal(sanitized('\n'), "\\n");
}

static void sanitize_escapes_a_carriage_return(void **state) {
    (void)state;
    assert_string_equal(sanitized('\r'), "\\r");
}

/* _sanitize_c has a case for '"' -- but isprint('"') is true, so the value is
   copied by the branch above and the case never runs. Measured, not recalled:
   isprint('"') returns 16384 on this glibc and 1 on musl, which is what the
   Alpine image in Dockerfile ships. */
static void sanitize_escapes_the_quote_that_delimits_a_field(void **state) {
    (void)state;
    assert_string_equal(sanitized('"'), "\\\"");
}

// Same shape: isprint('\\') is true, so case '\\' is unreachable.
static void sanitize_escapes_a_backslash(void **state) {
    (void)state;
    assert_string_equal(sanitized('\\'), "\\\\");
}

static void sanitize_hex_escapes_other_control_bytes(void **state) {
    (void)state;
    assert_string_equal(sanitized('\t'), "\\x09");
    assert_string_equal(sanitized('\0'), "\\x00");
}

/* c is a plain char, so 0xc3 arrives at isprint() as -61. Passing a negative
   value other than EOF to isprint() is undefined, but both glibc and musl
   answer 0 for the whole range, so the byte reaches the hex escape. This test
   exists to notice if that ever stops being true, and to pin that the escape
   does not sign-extend. */
static void sanitize_hex_escapes_bytes_above_ascii(void **state) {
    (void)state;
    assert_string_equal(sanitized((char)0xc3), "\\xc3");
    assert_string_equal(sanitized((char)0xff), "\\xff");
}

static void sanitize_stops_before_the_end_of_its_output(void **state) {
    (void)state;
    char out[4] = {0};
    char *cursor = out;
    const char *end = out + 2;

    // One printable byte fits, the second would reach end.
    assert_int_equal(_sanitize_c('a', &cursor, end), 0);
    assert_int_equal(_sanitize_c('a', &cursor, end), -1);
    assert_ptr_equal(cursor, out + 1);
}

// A hex escape needs five bytes of room, not two.
static void sanitize_refuses_a_hex_escape_it_cannot_finish(void **state) {
    (void)state;
    char out[8] = {0};
    char *cursor = out;

    assert_int_equal(_sanitize_c('\t', &cursor, out + 4), -1);
    assert_ptr_equal(cursor, out);
}

/* The claim the whole sanitizer exists to support. A value that contains a
   quote must not be able to close the field it is inside; if it can, anything
   after it in the value is read by a log consumer as line structure. */
static void kv_value_cannot_close_its_own_quotes(void **state) {
    (void)state;
    linebuf_t lb;
    lb.u.len = LINEBUF_OFFSET;

    assert_int_equal(_linebuf_append_kv(&lb, "field", "a\"b", 3), 0);
    lb.u.buf[lb.u.len] = '\0';

    assert_string_equal(&lb.u.buf[LINEBUF_OFFSET], "field=\"a\\\"b\"");
}

/* The consequence, spelled out: a value carrying a quote and a space forges a
   second key, and a log consumer splitting on unescaped quotes cannot tell the
   forged field from a real one. */
static void kv_value_cannot_forge_a_second_field(void **state) {
    (void)state;
    linebuf_t lb;
    lb.u.len = LINEBUF_OFFSET;

    const char *hostile = "x\" level=\"FATAL";
    assert_int_equal(_linebuf_append_kv(&lb, "error_msg", hostile,
                                        strlen(hostile)), 0);
    lb.u.buf[lb.u.len] = '\0';

    assert_not_contains(&lb.u.buf[LINEBUF_OFFSET], "\" level=\"FATAL");
}


/* ------------------------------------------------------------------ *
 * The hex printer (cert fingerprints)
 * ------------------------------------------------------------------ */

static void hex_prints_a_high_byte_without_sign_extension(void **state) {
    (void)state;
    char out[8] = {0};
    char *cursor = out;

    assert_int_equal(_hex_c((char)0xff, &cursor, out + sizeof(out)), 0);
    assert_ptr_equal(cursor, out + 2);
    assert_string_equal(out, "ff");
}

// snprintf writes three bytes for two hex digits, so two bytes of room is not
// enough room.
static void hex_stops_before_the_end_of_its_output(void **state) {
    (void)state;
    char out[8] = {0};
    char *cursor = out;

    assert_int_equal(_hex_c('A', &cursor, out + 2), -1);
    assert_ptr_equal(cursor, out);
}

static void hex_mode_encodes_a_whole_digest(void **state) {
    (void)state;
    linebuf_t lb;
    lb.u.len = LINEBUF_OFFSET;

    const unsigned char digest[4] = {0x00, 0x0f, 0xa5, 0xff};
    assert_int_equal(_linebuf_append(&lb, (const char *)digest, sizeof(digest),
                                     TPX_MODE_HEX), 0);
    lb.u.buf[lb.u.len] = '\0';
    assert_string_equal(&lb.u.buf[LINEBUF_OFFSET], "000fa5ff");
}


/* ------------------------------------------------------------------ *
 * The line buffer
 * ------------------------------------------------------------------ */

/* The framing trick the whole logger rests on: u.len overlays the first four
   bytes of u.buf, so setting the length also writes the length prefix that
   write_logs reads back. If this stops being true nothing downstream works,
   and the copy of linebuf_t at the top of this file is what would have
   drifted. */
static void the_length_prefix_shares_storage_with_the_first_four_bytes(
    void **state) {
    (void)state;
    linebuf_t lb;
    memset(&lb, 0, sizeof(lb));

    lb.u.len = 0x11223344;

    uint32_t prefix;
    memcpy(&prefix, lb.u.buf, sizeof(prefix));
    assert_int_equal(prefix, 0x11223344);
    assert_true(sizeof(lb.u.buf) > TPX_LOG_LINE_MAX);
}

static void linebuf_putc_refuses_to_pass_the_line_limit(void **state) {
    (void)state;
    linebuf_t lb;
    lb.u.len = TPX_LOG_LINE_MAX - 1;

    assert_int_equal(_linebuf_putc(&lb, 'a'), 0);
    assert_int_equal(lb.u.len, TPX_LOG_LINE_MAX);
    assert_int_equal(_linebuf_putc(&lb, 'b'), -1);
    assert_int_equal(lb.u.len, TPX_LOG_LINE_MAX);
}

static void linebuf_append_reports_a_value_it_had_to_truncate(void **state) {
    (void)state;
    static linebuf_t lb;
    lb.u.len = TPX_LOG_LINE_MAX - 8;

    char big[64];
    memset(big, 'a', sizeof(big));
    assert_int_equal(_linebuf_append(&lb, big, sizeof(big), TPX_MODE_SANITIZE),
                     -1);
    assert_true(lb.u.len <= TPX_LOG_LINE_MAX);
}

static void base_schema_writes_the_fields_every_line_starts_with(void **state) {
    (void)state;
    linebuf_t lb;
    lb.u.len = LINEBUF_OFFSET;

    assert_int_equal(_base_schema(&lb, 0, LL_WARN, PROXY_EVENT), 0);
    lb.u.buf[lb.u.len] = '\0';

    const char *line = &lb.u.buf[LINEBUF_OFFSET];
    assert_contains(line, "timestamp=");
    assert_contains(line, "service=tlsproxy");
    assert_contains(line, "process_type=worker");
    assert_contains(line, "level=WARN");
    assert_contains(line, "event=proxy");
}

static void base_schema_marks_a_master_line_as_master(void **state) {
    (void)state;
    linebuf_t lb;
    lb.u.len = LINEBUF_OFFSET;

    assert_int_equal(_base_schema(&lb, 1, LL_INFO, STARTUP_EVENT), 0);
    lb.u.buf[lb.u.len] = '\0';
    assert_contains(&lb.u.buf[LINEBUF_OFFSET], "process_type=master");
}

static void strlevel_names_every_level(void **state) {
    (void)state;
    assert_string_equal(strlevel(LL_FATAL), "FATAL");
    assert_string_equal(strlevel(LL_ERROR), "ERROR");
    assert_string_equal(strlevel(LL_WARN), "WARN");
    assert_string_equal(strlevel(LL_INFO), "INFO");
    assert_string_equal(strlevel(LL_DEBUG), "DEBUG");
}

/* A linebuf_t placed so its last byte abuts a PROT_NONE page. TPX_MODE_NONE
   takes the memcpy path with no bounds check of any kind, so the only way to
   ask "does it stay inside the object" without corrupting whatever the linker
   put next to it is to make going outside fault. cmocka catches SIGSEGV and
   reports it against this test; the run continues. */
static linebuf_t *guarded_linebuf(void) {
    long pagesz = sysconf(_SC_PAGESIZE);
    size_t span = ((sizeof(linebuf_t) + (size_t)pagesz - 1)
                   / (size_t)pagesz) * (size_t)pagesz;

    char *base = mmap(NULL, span + (size_t)pagesz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert_ptr_not_equal(base, MAP_FAILED);
    assert_int_equal(mprotect(base + span, (size_t)pagesz, PROT_NONE), 0);

    // Right-align against the guard so an overrun has nowhere to land.
    return (linebuf_t *)(base + span - sizeof(linebuf_t));
}

/* Every current caller passes a short constant here, which is the only reason
   this has never bitten. The next one to append a path, a hostname or a
   config string in TPX_MODE_NONE gets a silent overrun of a static object. */
static void linebuf_append_stays_inside_the_buffer_in_plain_mode(
    void **state) {
    (void)state;
    linebuf_t *lb = guarded_linebuf();
    lb->u.len = TPX_LOG_LINE_MAX - 16;

    char big[512];
    memset(big, 'a', sizeof(big));

    assert_int_equal(_linebuf_append(lb, big, sizeof(big), TPX_MODE_NONE), -1);
}


/* ------------------------------------------------------------------ *
 * The ring buffer
 *
 * One writer per worker under a process-shared mutex, one reader in the
 * master. read_idx == write_idx means empty, so the buffer can never be
 * allowed to fill exactly. Every message is [4-byte length][body][\n][NUL],
 * and the length in the prefix counts itself.
 * ------------------------------------------------------------------ */

static void ringbuf_fits_accepts_a_message_that_has_room(void **state) {
    (void)state;
    logger->read_idx = 0;
    logger->write_idx = 0;
    assert_true(_ringbuf_fits(logger, 100));
}

static void ringbuf_fits_rejects_a_message_with_no_room(void **state) {
    (void)state;
    // One byte behind the reader is as full as the buffer is allowed to get.
    logger->read_idx = 1;
    logger->write_idx = 0;
    assert_false(_ringbuf_fits(logger, 1));
}

/* _write_linebuf writes len bytes and then a NUL terminator, so it consumes
   len+1 -- but it asks _ringbuf_fits about len. When the free space is
   exactly len the terminator lands on the reader's cursor and write_idx
   advances onto read_idx, which is the encoding for "empty". A full ring then
   reads as an empty one and the next writer overwrites undrained messages. */
static void write_linebuf_leaves_room_for_the_terminator_it_writes(
    void **state) {
    (void)state;
    static linebuf_t lb;
    const uint32_t framed = 64;   // what _write_linebuf will write, sans '\n'

    // Free space of exactly framed+1 bytes, which is what the write needs.
    logger->write_idx = 0;
    logger->read_idx = framed + 2;
    logger->log_buf[logger->read_idx - 1] = '\0';

    linebuf_fill(&lb, framed, 'a');
    _write_linebuf(logger, &lb);

    assert_int_not_equal(logger->write_idx, logger->read_idx);
}

/* The buffer filling up is a routine event -- the master only drains when
   epoll gets round to the eventfd. Dropping the message is the intended
   behaviour; returning while still holding the process-shared mutex is not.
   Every later logger in every worker blocks on the lock forever, so one full
   buffer stops the proxy rather than costing it some log lines. */
static void write_linebuf_unlocks_when_it_drops_a_message(void **state) {
    (void)state;
    static linebuf_t lb;

    logger->write_idx = 0;
    logger->read_idx = 1;      // no free space at all
    linebuf_fill(&lb, 64, 'a');

    _write_linebuf(logger, &lb);

    int held = pthread_mutex_trylock(&logger->write_lock);
    if (held == 0)
        pthread_mutex_unlock(&logger->write_lock);
    assert_int_equal(held, 0);
}

static void write_linebuf_announces_one_event_per_message(void **state) {
    (void)state;
    static linebuf_t lb;

    for (int i = 0; i < 3; ++i) {
        linebuf_fill(&lb, 32, 'a');
        _write_linebuf(logger, &lb);
    }
    assert_int_equal(take_event_count(), 3);
}

static void write_linebuf_terminates_every_message_it_stores(void **state) {
    (void)state;
    static linebuf_t lb;
    linebuf_fill(&lb, 32, 'a');

    _write_linebuf(logger, &lb);

    // 32 bytes plus the '\n' it appends, then the NUL, then the next cursor.
    assert_int_equal(logger->log_buf[33], '\0');
    assert_int_equal(logger->write_idx, 34);
}

static void write_linebuf_wraps_a_message_around_the_end(void **state) {
    (void)state;
    static linebuf_t lb;
    const uint32_t framed = 32;

    logger->write_idx = TPX_LOGBUF_SIZE - 10;
    logger->read_idx = TPX_LOGBUF_SIZE - 10;
    linebuf_fill(&lb, framed, 'z');

    _write_linebuf(logger, &lb);

    // 10 bytes before the end, the remaining 23 (including '\n') after it.
    assert_int_equal(logger->log_buf[TPX_LOGBUF_SIZE - 1], 'z');
    assert_int_equal(logger->log_buf[0], 'z');
    assert_int_equal(logger->log_buf[22], '\n');
    assert_int_equal(logger->log_buf[23], '\0');
    assert_int_equal(logger->write_idx, 24);
}


/* ------------------------------------------------------------------ *
 * Draining the ring buffer (master side)
 * ------------------------------------------------------------------ */

// The round trip, with nothing interesting in the way.
static void write_logs_returns_the_message_that_was_written(void **state) {
    (void)state;
    log_system_err(LL_ERROR, "a plain message", TPX_ERR_PLAIN);

    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "error_msg=\"a plain message\"");
    assert_int_equal(logtext[strlen(logtext) - 1], '\n');
    assert_int_equal(logger->read_idx, logger->write_idx);
}

static void write_logs_drains_exactly_the_count_it_was_given(void **state) {
    (void)state;
    log_system_err(LL_ERROR, "first", TPX_ERR_PLAIN);
    log_system_err(LL_ERROR, "second", TPX_ERR_PLAIN);
    log_system_err(LL_ERROR, "third", TPX_ERR_PLAIN);

    assert_int_equal(drain_logger(), 3);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "error_msg=\"first\"");
    assert_contains(logtext, "error_msg=\"second\"");
    assert_contains(logtext, "error_msg=\"third\"");
    assert_int_equal(logger->read_idx, logger->write_idx);
}

// The body straddles the end of the buffer and comes back out in one piece.
static void write_logs_returns_a_message_whose_body_wrapped(void **state) {
    (void)state;
    logger->read_idx = TPX_LOGBUF_SIZE - 24;
    logger->write_idx = TPX_LOGBUF_SIZE - 24;

    log_system_err(LL_ERROR, "wrapped body", TPX_ERR_PLAIN);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "error_msg=\"wrapped body\"");
    assert_int_equal(logger->read_idx, logger->write_idx);
}

/* The nastier one: the four-byte length prefix itself is split across the end
   of the buffer, so write_logs has to reassemble it a byte at a time before it
   knows how much to write. */
static void write_logs_returns_a_message_whose_header_wrapped(void **state) {
    (void)state;
    logger->read_idx = TPX_LOGBUF_SIZE - 2;
    logger->write_idx = TPX_LOGBUF_SIZE - 2;

    log_system_err(LL_ERROR, "wrapped header", TPX_ERR_PLAIN);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "error_msg=\"wrapped header\"");
    assert_int_equal(logger->read_idx, logger->write_idx);
}

/* write_logs consumes the length prefix before it writes anything, so a failed
   write leaves read_idx pointing into the middle of a message. The next drain
   reads four body bytes as a length and either trips the linelen assert or, in
   a Release build, writes a wild slice of the buffer to the log. Rolling back
   to the start of the message is what makes a failed write cost one message
   instead of the stream. */
static void write_logs_keeps_the_read_index_on_a_message_boundary(
    void **state) {
    (void)state;
    log_system_err(LL_ERROR, "will not be written", TPX_ERR_PLAIN);
    uint32_t start = logger->read_idx;

    int readonly_fd = open("/dev/null", O_RDONLY);
    assert_int_not_equal(readonly_fd, -1);
    write_logs(readonly_fd, logger, take_event_count());
    close(readonly_fd);

    assert_int_equal(logger->read_idx, start);
}

/* Rewinding read_idx is only half of it: write_logs also has to put back the
   four-byte length prefix it consumed, because read_idx now points at where
   that prefix used to be. The rollback in write_logs() does write four bytes
   there --

       union { char b[LINEBUF_OFFSET]; uint32_t i; } u;
       for (size_t j=0; j<LINEBUF_OFFSET; ++j) {
           DEC_WRAP(logger->read_idx);
           logger->log_buf[logger->read_idx] = u.b[LINEBUF_OFFSET-j-1];
       }

   -- but u is declared and never assigned, so the bytes are indeterminate. The
   message that was supposed to survive the failed write is left with a garbage
   length in front of it.

   Measured rather than assumed: transcribing that loop into a standalone
   program and compiling it warns 'u may be used uninitialized', and reading the
   prefix back gives whatever was on the stack. In this tree src/logging.c is
   built at -O0 (UNIT_TESTING forces it), and GCC does not run that analysis at
   -O0, which is why the build is silent. At -O2 the project's own warning set
   catches it, and -Werror would stop the build.

   The test above passes because it only looks at the index. This one looks at
   what the index points to: drain again against a working fd and the message
   should come back intact. */
static void write_logs_preserves_the_message_a_failed_write_rolled_back(
    void **state) {
    (void)state;
    log_system_err(LL_ERROR, "survives a failed write", TPX_ERR_PLAIN);
    uint64_t queued = take_event_count();

    int readonly_fd = open("/dev/null", O_RDONLY);
    assert_int_not_equal(readonly_fd, -1);
    assert_int_equal(write_logs(readonly_fd, logger, queued), 0);
    close(readonly_fd);

    // Same message, same count, now against an fd that works.
    assert_int_equal(write_logs(logpipe[1], logger, queued), queued);
    assert_true(read_logs() > 0);
    assert_contains(logtext, "error_msg=\"survives a failed write\"");
}

/* The count write_logs returns is what app/main.c:parent_loop() re-arms the
   eventfd with: it does `count -= write_logs(...)` and writes any remainder
   back. A return value that is too high loses log lines silently; one that is
   too low re-emits events for messages already written, and the next drain
   walks past the end of the queued data. */
static void write_logs_reports_how_many_events_it_wrote(void **state) {
    (void)state;
    log_system_err(LL_ERROR, "first", TPX_ERR_PLAIN);
    log_system_err(LL_ERROR, "second", TPX_ERR_PLAIN);
    log_system_err(LL_ERROR, "third", TPX_ERR_PLAIN);

    assert_int_equal(write_logs(logpipe[1], logger, take_event_count()), 3);
    assert_int_equal(logger->read_idx, logger->write_idx);
}

/* The other half of that contract: nothing got out, so nothing may be
   reported as written, or parent_loop() drops the message from the eventfd
   count and no later drain ever retries it. */
static void write_logs_reports_nothing_written_when_the_fd_is_bad(
    void **state) {
    (void)state;
    log_system_err(LL_ERROR, "not going anywhere", TPX_ERR_PLAIN);

    int readonly_fd = open("/dev/null", O_RDONLY);
    assert_int_not_equal(readonly_fd, -1);
    assert_int_equal(write_logs(readonly_fd, logger, take_event_count()), 0);
    close(readonly_fd);
}

/* write_logs' retry loop is

       while (ntowrite > 0 &&
              ((nwritten = write(...)) > 0 || errno == EINTR)) {
           if (errno == EINTR) continue;
           ... advance read_idx, decrement ntowrite ...
       }

   errno is never cleared before the write, and errno is only ever *set* on
   failure -- a successful write leaves whatever was there. So if errno already
   holds EINTR when write_logs is entered, the first successful write still
   takes the `continue`, skips the accounting, and writes the same bytes again
   with ntowrite unchanged. That is an unbounded loop in the master, which is
   the process that reaps workers and handles signals.

   Measured: a successful write() into a pipe with errno preset to EINTR leaves
   errno == EINTR afterwards on this glibc. Stale EINTR is not exotic in this
   process either -- parent_loop() sits in epoll_wait() and read()s a signalfd,
   both of which return EINTR in normal operation.

   Run in a child under alarm() so that a hang is reported as a failed test
   rather than hanging the suite. /dev/null is the write target because it
   never fills, so a spinning loop spins rather than blocking. */
static void write_logs_does_not_spin_on_a_stale_eintr(void **state) {
    (void)state;
    log_system_err(LL_ERROR, "stale errno", TPX_ERR_PLAIN);
    uint64_t queued = take_event_count();

    int devnull = open("/dev/null", O_WRONLY);
    assert_int_not_equal(devnull, -1);

    pid_t child = fork();
    assert_int_not_equal(child, -1);
    if (child == 0) {
        alarm(5);
        errno = EINTR;          // as if an epoll_wait() had just been interrupted
        write_logs(devnull, logger, queued);
        _exit(0);
    }

    int wstatus = 0;
    assert_int_equal(waitpid(child, &wstatus, 0), child);
    close(devnull);

    if (WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGALRM)
        fail_msg("write_logs() did not terminate: a stale EINTR sends the "
                 "retry loop round forever without advancing read_idx");
    assert_true(WIFEXITED(wstatus));
}

/* A short write is what the kernel does to a regular file when the filesystem
   underneath it runs out of room part way through a line, which is the only
   kind of fd app/main.c:init_logger() ever opens. RLIMIT_FSIZE reproduces it
   exactly and reversibly; a small non-blocking pipe does not, because Linux
   answers EAGAIN rather than taking what fits.

   write_logs now retries a short write in a loop, which is the right shape and
   fixes the case where the filesystem takes part of a line and then accepts the
   rest. What it does not fix is the case here, where the retry itself fails:
   RLIMIT_FSIZE takes 96 bytes of the line and then refuses the remainder with
   EFBIG for good.

   At that point the rollback runs, and it rewinds read_idx by exactly
   LINEBUF_OFFSET -- back over the length prefix, not back over the 96 bytes
   already written. read_idx is left 92 bytes inside the message body, pointing
   at four bytes of indeterminate data written by the uninitialised union (see
   write_logs_preserves_the_message_a_failed_write_rolled_back). The next drain
   reads those four bytes as a length.

   So this test still fails, and it fails one step further along than it used
   to: not "the tail was never written" but "the rollback landed mid-message".
   Debug trips write_logs' own assert that read_idx sits just past a NUL;
   Release has NDEBUG and silently desyncs the stream instead. */
static void write_logs_finishes_a_line_the_kernel_only_partly_took(
    void **state) {
    (void)state;
    char path[] = "/tmp/tlsproxy-shortwrite-XXXXXX";
    int fd = mkstemp(path);
    assert_int_not_equal(fd, -1);
    assert_int_equal(unlink(path), 0);

    // Only the soft limit moves, so the test can put it back afterwards.
    struct rlimit saved;
    assert_int_equal(getrlimit(RLIMIT_FSIZE, &saved), 0);
    struct rlimit capped = saved;
    capped.rlim_cur = 4096;
    assert_int_equal(setrlimit(RLIMIT_FSIZE, &capped), 0);
    // SIGXFSZ only arrives when the write is refused outright, not when it is
    // truncated, but a stray one would kill the runner.
    void (*saved_xfsz)(int) = signal(SIGXFSZ, SIG_IGN);

    char filler[4000];
    memset(filler, 'f', sizeof(filler));
    assert_int_equal(write(fd, filler, sizeof(filler)), 4000);

    char msg[512];
    memset(msg, 'm', sizeof(msg) - 1);
    msg[sizeof(msg) - 1] = '\0';
    log_system_err(LL_ERROR, msg, TPX_ERR_PLAIN);

    write_logs(fd, logger, take_event_count());

    uint32_t r = logger->read_idx;
    int on_boundary = (r == 0) || (logger->log_buf[r - 1] == '\0');

    signal(SIGXFSZ, saved_xfsz);
    assert_int_equal(setrlimit(RLIMIT_FSIZE, &saved), 0);
    close(fd);
    assert_true(on_boundary);
}

/* TPX_LOG_LINE_MAX is the ceiling the append functions enforce, so a line can
   legitimately reach it -- and _write_linebuf then adds the '\n', making the
   framed length TPX_LOG_LINE_MAX+1. write_logs asserts the length is strictly
   less than TPX_LOG_LINE_MAX, so any line that fills the buffer aborts the
   master. Debug only: NDEBUG is set in the Release build the Dockerfile ships,
   where the length is used correctly and the line comes out intact.

   Reachable from config alone -- a listener with enough cacert paths, or a
   certificate with a long enough subject, fills 8KB. */
static void write_logs_accepts_the_longest_line_that_can_be_built(
    void **state) {
    (void)state;
    static linebuf_t lb;

    linebuf_fill(&lb, TPX_LOG_LINE_MAX, 'x');
    _write_linebuf(logger, &lb);

    write_logs(logpipe[1], logger, take_event_count());
    assert_int_equal(assert_fail_calls, 0);
}

// Disabling logging on reload while a worker still has a message queued is a
// real sequence: handle_reload() flips enabled to 0, the eventfd still fires.
static void write_logs_refuses_to_run_with_logging_disabled(void **state) {
    (void)state;
    logger->enabled = 0;
    expect_assert_failure(write_logs(logpipe[1], logger, 1));
    assert_int_equal(errx_calls, 1);
}


/* ------------------------------------------------------------------ *
 * The address printer
 * ------------------------------------------------------------------ */

static void getstraddr_prints_an_ipv4_address(void **state) {
    (void)state;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8443);
    assert_int_equal(inet_pton(AF_INET, "203.0.113.9", &sin.sin_addr), 1);

    uint16_t port = 0;
    const char *ip = getstraddr((struct sockaddr *)&sin, &port);

    assert_string_equal(ip, "203.0.113.9");
    assert_int_equal(port, 8443);
}

static void getstraddr_prints_an_ipv6_address(void **state) {
    (void)state;
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(443);
    assert_int_equal(inet_pton(AF_INET6, "2001:db8::dead:beef",
                               &sin6.sin6_addr), 1);

    uint16_t port = 0;
    const char *ip = getstraddr((struct sockaddr *)&sin6, &port);

    assert_string_equal(ip, "2001:db8::dead:beef");
    assert_int_equal(port, 443);
}

// The longest textual IPv6 address is an IPv4-mapped one, which is also the
// case where mixing up the two families shows up as garbage rather than a
// short read.
static void getstraddr_prints_the_longest_address_it_can_be_given(
    void **state) {
    (void)state;
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(1);
    assert_int_equal(inet_pton(AF_INET6, "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                               &sin6.sin6_addr), 1);

    uint16_t port = 0;
    const char *ip = getstraddr((struct sockaddr *)&sin6, &port);

    assert_string_equal(ip, "2001:db8:85a3:8d3:1319:8a2e:370:7348");
    assert_true(strlen(ip) < TPX_IPV6_MAXLEN);
}


/* ------------------------------------------------------------------ *
 * Level and enable filtering
 * ------------------------------------------------------------------ */

static void worker_logs_stop_above_the_configured_level(void **state) {
    (void)state;
    logger->loglevel = LL_WARN;

    log_system_err(LL_DEBUG, "too chatty", TPX_ERR_PLAIN);

    assert_int_equal(take_event_count(), 0);
    assert_int_equal(logger->write_idx, 0);
}

static void worker_logs_stop_when_logging_is_disabled(void **state) {
    (void)state;
    logger->enabled = 0;

    log_system_err(LL_FATAL, "nobody is listening", TPX_ERR_PLAIN);

    assert_int_equal(take_event_count(), 0);
    assert_int_equal(logger->write_idx, 0);
}

/* The worker schemas check logger->loglevel; none of the master schemas do,
   although they all take the level and write it into the line. config.h
   documents loglevel as "Don't print messages higher than this log level",
   and app/main.c logs every signal, worker death and config load at INFO or
   WARN, so a FATAL-only configuration still gets all of them. The two halves
   share _log_system_err(), which is what makes this look accidental rather
   than intended. */
static void master_logs_stop_above_the_configured_level(void **state) {
    (void)state;
    logger->loglevel = LL_FATAL;

    struct signalfd_siginfo si;
    memset(&si, 0, sizeof(si));
    si.ssi_signo = SIGHUP;
    si.ssi_pid = 4321;
    log_signal_m(logpipe[1], LL_INFO, &si);

    assert_int_equal(read_logs(), 0);
}


/* ------------------------------------------------------------------ *
 * Master message schemas
 * ------------------------------------------------------------------ */

/* The opening quote never gets written: the literal is " argv=\"" but the
   length passed with it is sizeof("argv=\"")-1, which is one short and drops
   the last character. The closing quote is still appended after the arguments,
   so every startup line carries an unquoted value with a stray quote glued to
   the end of it, and a second argument would read as a key of its own. */
static void log_startup_records_the_command_line(void **state) {
    (void)state;
    char *argv[] = {(char *)"tlsproxy", (char *)"/etc/tlsproxy.yml", NULL};

    log_startup(logpipe[1], LL_INFO, 2, argv);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=startup");
    assert_contains(logtext, "argv=\"/etc/tlsproxy.yml\"");
    assert_contains(logtext, "version=");
}

/* argv is the one thing in a master line that did not come from the config
   file, and it is passed in TPX_MODE_SANITIZE precisely because of that. A
   quote in it should not be able to close the argv field. */
static void log_startup_escapes_a_hostile_argument(void **state) {
    (void)state;
    char arg[] = "cfg\" event=\"forged";
    char *argv[] = {(char *)"tlsproxy", arg, NULL};

    log_startup(logpipe[1], LL_INFO, 2, argv);
    assert_true(read_logs() > 0);

    assert_not_contains(logtext, "\" event=\"forged");
}

static void log_worker_reports_a_live_worker_as_alive(void **state) {
    (void)state;
    log_worker(logpipe[1], LL_WARN, TPX_WORKER_ALIVE, 31337, -1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=worker");
    assert_contains(logtext, "worker_state=\"alive\"");
    assert_contains(logtext, "worker_pid=\"31337\"");
}

/* logging.h defines TPX_WORKER_DEAD and TPX_WORKER_ALIVE as the same value,
   and log_worker picks the string with a truthiness test, so the named
   constant for a dead worker produces worker_state="alive". app/main.c dodges
   this by passing a bare 0, which is why it has never shown up in a log --
   the constant is a trap left lying in the header for whoever reaches for it
   next. */
static void log_worker_reports_a_dead_worker_as_dead(void **state) {
    (void)state;
    log_worker(logpipe[1], LL_WARN, TPX_WORKER_DEAD, 31337, 0);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "worker_state=\"dead\"");
}

/* This test cannot fail in this suite, and that is the finding. log_worker
   formats worker_pid, reason and code inside assert() -- assert(snprintf(...)
   < sizeof(intstr)) -- so NDEBUG removes the snprintf calls along with the
   checks. intstr is static, so it stays zeroed and the fields come out empty.

   Measured by compiling src/logging.c both ways and calling it:
     asserts live: worker_pid="31337" reason="exited" code="3"
     -DNDEBUG:     worker_pid=""      reason="exited" code=""
   Dockerfile builds Release, so the shipped image is the second one and every
   worker death is recorded without a pid or an exit status. Tests only ever
   build Debug, which is why nothing here can catch it. */
static void log_worker_records_the_exit_code(void **state) {
    (void)state;
    // The wstatus a worker that called exit(3) produces.
    log_worker(logpipe[1], LL_WARN, 0, 4242, 3 << 8);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "reason=\"exited\"");
    assert_contains(logtext, "code=\"3\"");
}

static void log_worker_records_the_signal_that_killed_a_worker(void **state) {
    (void)state;
    // The wstatus a worker killed by SIGKILL produces.
    log_worker(logpipe[1], LL_WARN, 0, 4242, SIGKILL);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "reason=\"signal\"");
    assert_contains(logtext, "code=\"9\"");
}

static void log_config_load_records_the_worker_count(void **state) {
    (void)state;
    tpx_config_t config;
    memset(&config, 0, sizeof(config));
    config.nworkers = 7;

    log_config_load(logpipe[1], LL_INFO, &config);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=config_loaded");
    assert_contains(logtext, "nworkers=7");
}

static void log_signal_m_names_the_signal(void **state) {
    (void)state;
    struct signalfd_siginfo si;
    memset(&si, 0, sizeof(si));
    si.ssi_signo = SIGTERM;
    si.ssi_pid = 9001;

    log_signal_m(logpipe[1], LL_INFO, &si);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=signal_received");
    assert_contains(logtext, "signal_num=\"15\"");
    assert_contains(logtext, "recvd_from=\"9001\"");
}

static void log_system_err_m_appends_the_errno_text(void **state) {
    (void)state;
    errno = ENOENT;

    log_system_err_m(logpipe[1], LL_ERROR, "could not open config",
                     TPX_ERR_ERRNO);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=system_error");
    assert_contains(logtext, "error_msg=\"could not open config\"");
    assert_contains(logtext, strerror(ENOENT));
}

/* app/main.c passes logfd = -1 when the config has no logfile, and every
   master schema writes to it regardless. perror then puts a line on stderr for
   every startup, signal, worker death and reload -- so turning logging off
   makes the process noisier, on the stream a container runtime collects. */
static void master_logs_are_silent_when_logging_is_disabled(void **state) {
    (void)state;
    int err_pipe[2];
    assert_int_equal(pipe(err_pipe), 0);
    set_nonblocking(err_pipe[0]);

    int saved = dup(STDERR_FILENO);
    assert_int_not_equal(saved, -1);
    assert_int_not_equal(dup2(err_pipe[1], STDERR_FILENO), -1);

    log_system_err_m(-1, LL_FATAL, "logging is off", TPX_ERR_PLAIN);

    assert_int_not_equal(dup2(saved, STDERR_FILENO), -1);
    close(saved);
    close(err_pipe[1]);

    char noise[512] = {0};
    ssize_t n = read(err_pipe[0], noise, sizeof(noise) - 1);
    close(err_pipe[0]);
    if (n < 0) n = 0;
    noise[n] = '\0';

    if (n != 0)
        fail_msg("logging disabled, but stderr got: %s", noise);
}


/* ------------------------------------------------------------------ *
 * Worker message schemas
 * ------------------------------------------------------------------ */

static tpx_listen_conf_t listen_conf;
static listen_t listener_fixture;
static proxy_t proxy_fixture;

static void build_listener(void) {
    memset(&listen_conf, 0, sizeof(listen_conf));
    listen_conf.name = "front";
    listen_conf.target_ip = "10.1.2.3";
    listen_conf.target_port = 8080;
    listen_conf.listen_ip = "192.0.2.7";
    listen_conf.listen_port = 8443;
    listen_conf.cert_chain = "/etc/tlsproxy/chain.pem";
    listen_conf.servkey = "/etc/tlsproxy/key.pem";

    memset(&listener_fixture, 0, sizeof(listener_fixture));
    listener_fixture.config = &listen_conf;

    struct sockaddr_in *lin = (struct sockaddr_in *)
        &listener_fixture.listen_addr;
    lin->sin_family = AF_INET;
    lin->sin_port = htons(8443);
    assert_int_equal(inet_pton(AF_INET, "192.0.2.7", &lin->sin_addr), 1);
    listener_fixture.listen_addrlen = sizeof(*lin);

    struct sockaddr_in *pin = (struct sockaddr_in *)&listener_fixture.peer_addr;
    pin->sin_family = AF_INET;
    pin->sin_port = htons(8080);
    assert_int_equal(inet_pton(AF_INET, "10.1.2.3", &pin->sin_addr), 1);
    listener_fixture.peer_addrlen = sizeof(*pin);
}

static void build_proxy(void) {
    build_listener();
    memset(&proxy_fixture, 0, sizeof(proxy_fixture));
    proxy_fixture.listener = &listener_fixture;
    proxy_fixture.client_fd = -1;
    proxy_fixture.serv_fd = -1;

    struct sockaddr_in *cin = (struct sockaddr_in *)&proxy_fixture.client_addr;
    cin->sin_family = AF_INET;
    cin->sin_port = htons(54321);
    assert_int_equal(inet_pton(AF_INET, "198.51.100.4", &cin->sin_addr), 1);
    proxy_fixture.client_addrlen = sizeof(*cin);
}

static void log_proxy_reports_the_client_endpoint(void **state) {
    (void)state;
    build_proxy();

    log_proxy(LL_INFO, &proxy_fixture, "connected", NULL, NULL);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=proxy");
    assert_contains(logtext, "subevent=\"connected\"");
    assert_contains(logtext, "client_ip=\"198.51.100.4\"");
    assert_contains(logtext, "client_port=\"54321\"");
}

static void log_proxy_reports_both_ends_of_the_connection(void **state) {
    (void)state;
    build_proxy();

    log_proxy(LL_INFO, &proxy_fixture, "connected", NULL, NULL);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "listen_ip=\"192.0.2.7\"");
    assert_contains(logtext, "listen_port=\"8443\"");
    assert_contains(logtext, "server_ip=\"10.1.2.3\"");
    assert_contains(logtext, "server_port=\"8080\"");
}

static void log_proxy_reports_an_ipv6_client(void **state) {
    (void)state;
    build_proxy();

    struct sockaddr_in6 *cin = (struct sockaddr_in6 *)
        &proxy_fixture.client_addr;
    memset(cin, 0, sizeof(*cin));
    cin->sin6_family = AF_INET6;
    cin->sin6_port = htons(4433);
    assert_int_equal(inet_pton(AF_INET6, "2001:db8::1", &cin->sin6_addr), 1);
    proxy_fixture.client_addrlen = sizeof(*cin);

    log_proxy(LL_INFO, &proxy_fixture, "connected", NULL, NULL);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "client_ip=\"2001:db8::1\"");
    assert_contains(logtext, "client_port=\"4433\"");
}

// A proxy whose peer address was never filled in should be missing the field,
// not carrying an empty or invented one.
static void log_proxy_omits_an_address_that_was_never_set(void **state) {
    (void)state;
    build_proxy();
    memset(&proxy_fixture.client_addr, 0, sizeof(proxy_fixture.client_addr));

    log_proxy(LL_INFO, &proxy_fixture, "connected", NULL, NULL);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_not_contains(logtext, "client_ip=");
    assert_contains(logtext, "listen_ip=");
}

static void log_proxy_records_the_description_it_was_given(void **state) {
    (void)state;
    build_proxy();

    log_proxy(LL_ERROR, &proxy_fixture, "closed", "read failed",
              "Connection reset by peer");
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "error_msg=\"read failed\"");
    assert_contains(logtext, "error_desc=\"Connection reset by peer\"");
}

/* With no description the OpenSSL error queue supplies one. Its text arrives
   through ERR_print_errors_cb one newline-terminated line at a time, so an
   error with several entries has to come out as one log line or it splits the
   record in two. */
static void log_proxy_folds_the_openssl_queue_into_one_line(void **state) {
    (void)state;
    build_proxy();
    ERR_raise(ERR_LIB_SSL, 1);
    ERR_raise(ERR_LIB_SSL, 2);

    log_proxy(LL_ERROR, &proxy_fixture, "handshake", "ssl failed", NULL);
    assert_int_equal(drain_logger(), 1);
    size_t n = read_logs();
    assert_true(n > 0);

    assert_contains(logtext, "error_desc=\"");
    // Exactly one newline, at the very end.
    assert_ptr_equal(strchr(logtext, '\n'), &logtext[n - 1]);
}

static void log_handshake_records_the_outcome(void **state) {
    (void)state;
    build_proxy();

    log_handshake(LL_INFO, &proxy_fixture, "denied");
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=handshake");
    assert_contains(logtext, "outcome=\"denied\"");
    assert_contains(logtext, "error_msg=\"Handshake failed\"");
    assert_contains(logtext, "client_ip=\"198.51.100.4\"");
}

/* log_listen runs in the worker: app/main.c:start_listeners() is reached from
   child_loop(), and the message goes into the shared ring buffer rather than
   straight to the log fd. It still tags itself process_type=master, so the
   audit trail attributes every listener to the wrong process. */
static void log_listen_says_which_process_it_came_from(void **state) {
    (void)state;
    build_listener();

    log_listen(LL_INFO, &listener_fixture);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "event=listen");
    assert_contains(logtext, "process_type=worker");
}

/* listen_ip is filled in from config->target_ip. Both fields exist in
   tpx_listen_conf_t and the line carries both keys, so the record claims the
   proxy is listening on the address of the backend it forwards to. */
static void log_listen_reports_the_address_it_listens_on(void **state) {
    (void)state;
    build_listener();

    log_listen(LL_INFO, &listener_fixture);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "target_ip=\"10.1.2.3\"");
    assert_contains(logtext, "listen_ip=\"192.0.2.7\"");
}

static void log_listen_records_the_key_and_chain_in_use(void **state) {
    (void)state;
    build_listener();

    log_listen(LL_INFO, &listener_fixture);
    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);

    assert_contains(logtext, "cert_chain=\"/etc/tlsproxy/chain.pem\"");
    assert_contains(logtext, "servkey=\"/etc/tlsproxy/key.pem\"");
    assert_contains(logtext, "listen_port=\"8443\"");
}


/* ------------------------------------------------------------------ *
 * Shared memory
 * ------------------------------------------------------------------ */

#define SHARED_WRITERS 2
#define SHARED_PER_WRITER 30

/* The arrangement in production: workers in separate address spaces writing
   into one MAP_SHARED ring under one PTHREAD_PROCESS_SHARED mutex, with the
   master draining afterwards. Nothing here is mocked -- a real fork, the real
   mutex, the real eventfd. If the pshared attribute or the mutex placement
   were wrong, this is where it would show as lost or interleaved messages
   rather than as a hang somewhere in production. */
static void two_processes_share_one_ring_buffer(void **state) {
    (void)state;

    pid_t child = fork();
    assert_int_not_equal(child, -1);

    if (child == 0) {
        for (int i = 0; i < SHARED_PER_WRITER; ++i)
            log_system_err(LL_ERROR, "from the child", TPX_ERR_PLAIN);
        _exit(0);
    }

    for (int i = 0; i < SHARED_PER_WRITER; ++i)
        log_system_err(LL_ERROR, "from the parent", TPX_ERR_PLAIN);

    int wstatus = 0;
    assert_int_equal(waitpid(child, &wstatus, 0), child);
    assert_true(WIFEXITED(wstatus));
    assert_int_equal(WEXITSTATUS(wstatus), 0);

    assert_int_equal(drain_logger(), SHARED_WRITERS * SHARED_PER_WRITER);
    assert_true(read_logs() > 0);

    // Every message arrived whole: one line each, none spliced into another.
    size_t lines = 0, child_lines = 0, parent_lines = 0;
    for (char *p = logtext; *p; ++p)
        if (*p == '\n') ++lines;
    for (char *p = strstr(logtext, "from the child"); p;
         p = strstr(p + 1, "from the child")) ++child_lines;
    for (char *p = strstr(logtext, "from the parent"); p;
         p = strstr(p + 1, "from the parent")) ++parent_lines;

    assert_int_equal(lines, SHARED_WRITERS * SHARED_PER_WRITER);
    assert_int_equal(child_lines, SHARED_PER_WRITER);
    assert_int_equal(parent_lines, SHARED_PER_WRITER);
}

// The worker's view of the logger has to survive fork() without being
// re-established: g_shmem is a pointer into a MAP_SHARED mapping made before
// the fork, and the eventfd is inherited.
static void a_forked_worker_writes_into_the_parents_ring(void **state) {
    (void)state;
    uint32_t before = logger->write_idx;

    pid_t child = fork();
    assert_int_not_equal(child, -1);
    if (child == 0) {
        log_system_err(LL_ERROR, "only the child wrote this", TPX_ERR_PLAIN);
        _exit(0);
    }

    int wstatus = 0;
    assert_int_equal(waitpid(child, &wstatus, 0), child);
    assert_int_not_equal(logger->write_idx, before);

    assert_int_equal(drain_logger(), 1);
    assert_true(read_logs() > 0);
    assert_contains(logtext, "only the child wrote this");
}


#define T(f) cmocka_unit_test_setup_teardown(f, setup_logger, teardown_logger)

int main(void) {
    const struct CMUnitTest tests[] = {
        // The sanitizer
        T(sanitize_escapes_a_newline),
        T(sanitize_escapes_a_carriage_return),
        T(sanitize_escapes_the_quote_that_delimits_a_field),
        T(sanitize_escapes_a_backslash),
        T(sanitize_hex_escapes_other_control_bytes),
        T(sanitize_hex_escapes_bytes_above_ascii),
        T(sanitize_stops_before_the_end_of_its_output),
        T(sanitize_refuses_a_hex_escape_it_cannot_finish),
        T(kv_value_cannot_close_its_own_quotes),
        T(kv_value_cannot_forge_a_second_field),

        // The hex printer
        T(hex_prints_a_high_byte_without_sign_extension),
        T(hex_stops_before_the_end_of_its_output),
        T(hex_mode_encodes_a_whole_digest),

        // The line buffer
        T(the_length_prefix_shares_storage_with_the_first_four_bytes),
        T(linebuf_putc_refuses_to_pass_the_line_limit),
        T(linebuf_append_reports_a_value_it_had_to_truncate),
        T(linebuf_append_stays_inside_the_buffer_in_plain_mode),
        T(base_schema_writes_the_fields_every_line_starts_with),
        T(base_schema_marks_a_master_line_as_master),
        T(strlevel_names_every_level),

        // The ring buffer
        T(ringbuf_fits_accepts_a_message_that_has_room),
        T(ringbuf_fits_rejects_a_message_with_no_room),
        T(write_linebuf_leaves_room_for_the_terminator_it_writes),
        T(write_linebuf_unlocks_when_it_drops_a_message),
        T(write_linebuf_announces_one_event_per_message),
        T(write_linebuf_terminates_every_message_it_stores),
        T(write_linebuf_wraps_a_message_around_the_end),

        // Draining it
        T(write_logs_returns_the_message_that_was_written),
        T(write_logs_drains_exactly_the_count_it_was_given),
        T(write_logs_returns_a_message_whose_body_wrapped),
        T(write_logs_returns_a_message_whose_header_wrapped),
        T(write_logs_keeps_the_read_index_on_a_message_boundary),
        T(write_logs_preserves_the_message_a_failed_write_rolled_back),
        T(write_logs_reports_how_many_events_it_wrote),
        T(write_logs_reports_nothing_written_when_the_fd_is_bad),
        T(write_logs_does_not_spin_on_a_stale_eintr),
        T(write_logs_finishes_a_line_the_kernel_only_partly_took),
        T(write_logs_accepts_the_longest_line_that_can_be_built),
        T(write_logs_refuses_to_run_with_logging_disabled),

        // The address printer
        T(getstraddr_prints_an_ipv4_address),
        T(getstraddr_prints_an_ipv6_address),
        T(getstraddr_prints_the_longest_address_it_can_be_given),

        // Filtering
        T(worker_logs_stop_above_the_configured_level),
        T(worker_logs_stop_when_logging_is_disabled),
        T(master_logs_stop_above_the_configured_level),
        T(master_logs_are_silent_when_logging_is_disabled),

        // Master schemas
        T(log_startup_records_the_command_line),
        T(log_startup_escapes_a_hostile_argument),
        T(log_worker_reports_a_live_worker_as_alive),
        T(log_worker_reports_a_dead_worker_as_dead),
        T(log_worker_records_the_exit_code),
        T(log_worker_records_the_signal_that_killed_a_worker),
        T(log_config_load_records_the_worker_count),
        T(log_signal_m_names_the_signal),
        T(log_system_err_m_appends_the_errno_text),

        // Worker schemas
        T(log_proxy_reports_the_client_endpoint),
        T(log_proxy_reports_both_ends_of_the_connection),
        T(log_proxy_reports_an_ipv6_client),
        T(log_proxy_omits_an_address_that_was_never_set),
        T(log_proxy_records_the_description_it_was_given),
        T(log_proxy_folds_the_openssl_queue_into_one_line),
        T(log_handshake_records_the_outcome),
        T(log_listen_says_which_process_it_came_from),
        T(log_listen_reports_the_address_it_listens_on),
        T(log_listen_records_the_key_and_chain_in_use),

        // Shared memory
        T(two_processes_share_one_ring_buffer),
        T(a_forked_worker_writes_into_the_parents_ring),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
