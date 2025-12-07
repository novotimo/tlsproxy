#include "queue.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include <string.h>


void *__real_malloc(const size_t size);
void *__wrap_malloc(const size_t size) {
    if (has_mock())
        return (void *)mock();
    else
        return __real_malloc(size);
}

void *__real_calloc(size_t n, size_t size);
void *__wrap_calloc(size_t n, size_t size) {
    if (has_mock())
        return (void *)mock();
    else
        return __real_calloc(n, size);
}

/* If we fail to allocate a queue, return NULL */
static void new_queue(void **state) {
    will_return(__wrap_calloc, NULL);
    bufq_t *q = queue_new();
    assert_null(q);
}

/* If we fail to make a new member in the queue, return TPX_FAILURE */
static void enqueue_fail(void **state) {
    bufq_t *q = queue_new();
    assert_non_null(q);
    will_return(__wrap_malloc, NULL);
    assert_int_equal(enqueue(q,NULL,0),TPX_FAILURE);
    
    queue_free(q);
}

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

    free(buf);
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
    queue_free(q);
}

/* See that peek first and peek last work */
static void peek_first_last(void **state) {
    bufq_t *q = queue_new();
    unsigned char *dummy1 = malloc(1);
    unsigned char *dummy2 = malloc(2);
    assert_non_null(dummy1);
    assert_non_null(dummy2);
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

/* See that the queue inconsistency checks work */
static void inconsistent_queue(void **state) {
    // The queue functions return TPX_FAILURE when queue is NULL
    assert_int_equal(enqueue(NULL,NULL,0),TPX_FAILURE);
    assert_int_equal(dequeue(NULL,NULL,NULL),TPX_FAILURE);
    assert_int_equal(queue_peek(NULL,NULL,NULL),TPX_FAILURE);
    assert_int_equal(queue_peek_last(NULL,NULL,NULL),TPX_FAILURE);
    
    bufq_t *q = queue_new();

    // When the last pointer is broken, we fail and don't modify the queue
    enqueue(q, NULL, 0);
    q->last = NULL;
    bufq_t *q_copy = malloc(sizeof(bufq_t));
    memcpy(q_copy, q, sizeof(bufq_t));

    assert_int_equal(enqueue(q,NULL,0),TPX_FAILURE);
    assert_memory_equal(q,q_copy,sizeof(bufq_t));

    assert_int_equal(dequeue(q,NULL,NULL),TPX_FAILURE);
    assert_memory_equal(q,q_copy,sizeof(bufq_t));

    assert_int_equal(queue_peek(q,NULL,NULL),TPX_FAILURE);
    assert_memory_equal(q,q_copy,sizeof(bufq_t));
    
    assert_int_equal(queue_peek_last(q,NULL,NULL),TPX_FAILURE);
    assert_memory_equal(q,q_copy,sizeof(bufq_t));

    free(q_copy);
    // Also see if consistency checker cheks for first being null when last isn't
    q->last = q->first;
    q->first = NULL;

    assert_int_equal(enqueue(q,NULL,0),TPX_FAILURE);

    // Fix the queue so that no memory is leaked when freeing
    q->first = q->last;
    
    queue_free(q);
}

/* Make sure that peeks on empty queues give TPX_EMPTY */
static void peek_empty(void **state) {
    bufq_t *q = queue_new();

    assert_int_equal(queue_peek(q,NULL,NULL),TPX_EMPTY);
    assert_int_equal(queue_peek_last(q,NULL,NULL),TPX_EMPTY);

    enqueue(q,NULL,0);
    dequeue(q,NULL,NULL);
    
    assert_int_equal(queue_peek(q,NULL,NULL),TPX_EMPTY);
    assert_int_equal(queue_peek_last(q,NULL,NULL),TPX_EMPTY);
    
    queue_free(q);
}

/* Make sure that queue_free doesn't try to free the elements of inconsistent
   queues, because there's an opportunity for double frees */
static void free_inconsistent(void **state) {
    bufq_t *q = queue_new();
    unsigned char *buf = malloc(7);
    enqueue(q, buf, 7);
    bufq_elem_t *elem = q->first;
    q->first = NULL;

    // This works since the tests are run with addr sanitizers and so if one of
    // these isn't freed, or if there's a double free, the test will fail.
    queue_free(q);
    free(elem);
    free(buf);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_queue_valid),
        cmocka_unit_test(buf_returned_unmolested),
        cmocka_unit_test(empty_queues),
        cmocka_unit_test(write_idx),
        cmocka_unit_test(dequeue_empty),
        cmocka_unit_test(peek_first_last),
        cmocka_unit_test(inconsistent_queue),
        cmocka_unit_test(peek_empty),
        cmocka_unit_test(free_inconsistent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
