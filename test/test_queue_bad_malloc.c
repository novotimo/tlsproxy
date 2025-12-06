#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "queue.h"

void *__wrap_malloc(size_t size) {
    return NULL;
}

void *__wrap_calloc(size_t n, size_t size) {
    return NULL;
}

static void new_queue(void **state) {
    bufq_t *q = queue_new();
    assert_null(q);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_queue),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
