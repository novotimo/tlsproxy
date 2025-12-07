#include "queue.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>


void *__real__test_malloc(const size_t size, const char *file, const int line);
void *__wrap__test_malloc(size_t size) {
    int fail = (int) mock();
    if (fail)
        return NULL;
    else
        return __real__test_malloc(size, __FILE__, __LINE__);
}


void *__real__test_calloc(size_t n, size_t size, const char *file,
                          const int line);
void *__wrap__test_calloc(size_t n, size_t size) {
    int fail = (int) mock();
    if (fail)
        return NULL;
    else
        return __real__test_calloc(n, size, __FILE__, __LINE__);
}

static void new_queue(void **state) {
    will_return(__wrap__test_calloc, 1);
    bufq_t *q = queue_new();
    assert_null(q);
}

static void enqueue_fail(void **state) {
    will_return(__wrap__test_calloc, 0);
    bufq_t *q = queue_new();
    assert_non_null(q);
    will_return(__wrap__test_malloc, 1);
    assert_int_equal(enqueue(q,NULL,0),TPX_FAILURE);
    
    queue_free(q);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_queue),
        cmocka_unit_test(enqueue_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
