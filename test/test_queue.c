#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "queue.h"

/* This is what a new queue should look like. */
static void new_queue_valid(void **state) {
    bufq_t *q = queue_new();
    assert_non_null(q);
    assert_null(q->first);
    assert_null(q->last);
    assert_int_equal(q->read_idx, 0);
    assert_int_equal(q->write_idx, -1);

    queue_free(q);
}

/* A buffer should be returned exactly as it was. */
static void buf_returned_unmolested(void **state) {
    bufq_t *q = queue_new();

    void *buf = malloc(7);
    assert_non_null(buf);
    assert_int_equal(enqueue(q, buf, 7),TPX_SUCCESS);

    void *buf2 = NULL;
    size_t len2 = 0;
    assert_int_equal(dequeue(q, (unsigned char **)&buf2, &len2),TPX_SUCCESS);

    assert_ptr_equal(buf, buf2);
    assert_int_equal(7, len2);
    
    queue_free(q);
}

/* queue_empty() should work properly, as well as the TPX_EMPTY retcode */
static void empty_queues(void **state) {
    bufq_t *q = queue_new();

    for (uintptr_t i=0; i<7; ++i)
        assert_int_equal(enqueue(q, (unsigned char *)i, i),TPX_SUCCESS);
    assert_false(queue_empty(q));

    unsigned char *b;
    size_t l;
    for (int i=0; i<6; ++i) {
        assert_int_equal(dequeue(q, &b, &l), TPX_SUCCESS);
        assert_int_equal((uintptr_t)i,(uintptr_t)b);
        assert_int_equal(i, l);
    }
    assert_false(queue_empty(q));
    
    assert_int_equal(dequeue(q, &b, &l),TPX_SUCCESS);
    assert_int_equal((uintptr_t)6,(uintptr_t)b);
    assert_int_equal(6, l);
    assert_true(queue_empty(q));
    assert_int_equal(dequeue(q,NULL,NULL),TPX_EMPTY);
    
    queue_free(q);
}

/* write_idx should be >= 0 if there's a buffer and -1 otherwise */
static void write_idx(void **state) {
    bufq_t *q = queue_new();
    enqueue(q, NULL, 0);
    assert_non_null(q->first);
    assert_non_null(q->last);
    assert_int_equal(q->read_idx, 0);
    assert_int_equal(q->write_idx, 0);

    assert_null(q->first->buf);
    assert_int_equal(q->first->buflen, 0);
    assert_null(q->first->next);

    dequeue(q, NULL, NULL);
    
    assert_null(q->first);
    assert_null(q->last);
    assert_int_equal(q->read_idx, 0);
    assert_int_equal(q->write_idx, -1);
    queue_free(q);
}

/* Does calling dequeue on an empty queue mess anything up? */
static void dequeue_empty(void **state) {
    bufq_t *q = queue_new();
    for (int i=0; i<10; ++i)
        assert_int_equal(dequeue(q,NULL,NULL),TPX_EMPTY);
    assert_null(q->first);
    assert_null(q->last);
    assert_int_equal(q->read_idx, 0);
    assert_int_equal(q->write_idx, -1);
}

/* See that peek first and peek last work */
static void peek_first_last(void **state) {
    bufq_t *q = queue_new();
    unsigned char *dummy1 = malloc(1);
    unsigned char *dummy2 = malloc(2);
    enqueue(q, dummy1, 1);
    enqueue(q, dummy2, 2);

    unsigned char *b1, *b2;
    size_t l1, l2;
    queue_peek(q, &b1, &l1);
    queue_peek_last(q, &b2, &l2);
    // Get the right values
    assert_ptr_equal(b1,dummy1);
    assert_int_equal(l1,1);
    assert_ptr_equal(b2,dummy2);
    assert_int_equal(l2,2);

    // Make sure the values weren't changed
    queue_peek(q, &b2, &l2);
    queue_peek_last(q, &b1, &l1);
    assert_ptr_equal(b2,dummy1);
    assert_int_equal(l2,1);
    assert_ptr_equal(b1,dummy2);
    assert_int_equal(l1,2);

    queue_free(q);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_queue_valid),
        cmocka_unit_test(buf_returned_unmolested),
        cmocka_unit_test(empty_queues),
        cmocka_unit_test(write_idx),
        cmocka_unit_test(dequeue_empty),
        cmocka_unit_test(peek_first_last),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
