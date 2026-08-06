#include "queue.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "macros.h"
#include "shmem.h"


// Wrap functions for mocking
#define WRAPPED_FUNCS \
    WRAP_FUN(malloc, void *, (const size_t size), (size))               \
    WRAP_FUN(calloc, void *, (size_t n, size_t size), (n, size))

WRAPPED_FUNCS
#undef WRAP_FUN


/* This is what a new queue should look like. */
static void new_queue_valid(void **state) {
    bufq_t *q = queue_new();
    assert_non_null(q);
    assert_null(q->first);
    assert_null(q->last);
    assert_int_equal(q->read_idx, 0);
    assert_int_equal(q->write_idx, 0);

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

/* An enqueue onto an empty queue starts write_idx at 0, and draining the last
   element puts the queue back the way queue_new() left it */
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
    assert_int_equal(q->write_idx, 0);
    queue_free(q);
}

/* queue_empty() counts buffers, not bytes. A chunk whose data has all been
   sent out is still a chunk, and src/proxy.c:proxy_handle_read() has to write
   into it rather than append another, since the write path takes every chunk
   but the last for full and would send the unwritten tail of this one to the
   peer. */
static void queue_empty_counts_buffers_not_bytes(void **state) {
    bufq_t *q = queue_new();
    unsigned char *buf = malloc(16);
    assert_non_null(buf);
    assert_int_equal(enqueue(q, buf, 16), TPX_SUCCESS);

    // Everything written into the chunk has been read back out of it
    q->write_idx = 9;
    q->read_idx = 9;

    assert_false(queue_empty(q));

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
    assert_int_equal(q->write_idx, 0);
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

/* If we fail to allocate a queue, return NULL */
static void new_queue(void **state) {
    will_return_ptr(__wrap_calloc, NULL);
    bufq_t *q = queue_new();
    assert_null(q);
}

/* The queue reports through the logger now rather than to stderr, so what is
   worth pinning is that a failure reaches the log at all; how the line is
   formatted is test_logging.c's question and it has sixty-odd tests on it.
   write_idx moving is the whole of the claim, which is how test_logging.c asks
   it too. The logger goes back off afterwards, since the rest of this suite
   runs with it disabled and expects the silence. */
static void enqueue_failure_reaches_the_log(void **state) {
    bufq_t *q = queue_new();
    assert_non_null(q);

    pthread_mutexattr_t attrs;
    assert_int_equal(pthread_mutexattr_init(&attrs), 0);
    assert_int_equal(pthread_mutexattr_setpshared(&attrs,
                                                  PTHREAD_PROCESS_SHARED), 0);
    assert_int_equal(pthread_mutex_init(&g_shmem->logger.write_lock, &attrs),
                     0);
    assert_int_equal(pthread_mutexattr_destroy(&attrs), 0);

    /* A real eventfd rather than the zero the mapping starts at:
       _write_linebuf() writes the new line count to it to wake the master, and
       descriptor 0 is stdin. */
    g_shmem->logger.eventfd = eventfd(0, EFD_NONBLOCK);
    assert_int_not_equal(g_shmem->logger.eventfd, -1);
    g_shmem->logger.loglevel = LL_ERROR;
    g_shmem->logger.enabled = 1;

    uint32_t before = g_shmem->logger.write_idx;
    will_return_ptr(__wrap_malloc, NULL);
    assert_int_equal(enqueue(q, NULL, 0), TPX_FAILURE);
    assert_int_not_equal(g_shmem->logger.write_idx, before);

    g_shmem->logger.enabled = 0;
    close(g_shmem->logger.eventfd);
    g_shmem->logger.eventfd = -1;   // not a number a later write can reach
    queue_free(q);
}

/* If we fail to make a new member in the queue, return TPX_FAILURE */
static void enqueue_fail(void **state) {
    bufq_t *q = queue_new();
    assert_non_null(q);
    will_return_ptr(__wrap_malloc, NULL);
    assert_int_equal(enqueue(q,NULL,0),TPX_FAILURE);
    
    queue_free(q);
}


int main(void) {
    /* src/queue.c reports through the logger now, and log_system_err() reads
       g_shmem->logger.enabled before it decides to do nothing, so a queue
       error path segfaults on the unmapped pointer rather than returning the
       failure it is being asked about. Every other suite that reaches src/
       maps this; the queue suite did not have to until the queue started
       logging. enabled = 0 is what MAP_ANONYMOUS gives anyway and is here to
       say the silence is deliberate. */
    g_shmem = mmap(NULL, sizeof(shared_t), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert_non_null(g_shmem);
    g_shmem->logger.enabled = 0;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_queue_valid),
        cmocka_unit_test(buf_returned_unmolested),
        cmocka_unit_test(empty_queues),
        cmocka_unit_test(write_idx),
        cmocka_unit_test(queue_empty_counts_buffers_not_bytes),
        cmocka_unit_test(dequeue_empty),
        cmocka_unit_test(peek_first_last),
        cmocka_unit_test(inconsistent_queue),
        cmocka_unit_test(peek_empty),
        cmocka_unit_test(free_inconsistent),
        cmocka_unit_test(new_queue),
        cmocka_unit_test(enqueue_fail),
        cmocka_unit_test(enqueue_failure_reaches_the_log),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
