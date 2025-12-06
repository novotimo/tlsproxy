#ifndef __TLSPROXY_QUEUE_H
#define __TLSPROXY_QUEUE_H

#include <stdlib.h>

#include "errors.h"


/** @brief The buffer queue element */
typedef struct bufq_elem_s {
    struct bufq_elem_s *next; /**< @brief The next element in the bufq */
    unsigned char *buf; /**< @brief The buffer for this element */
    size_t buflen; /**< @brief The length of this buffer */
} bufq_elem_t;

/** @brief The buffer queue, as simple as it can be */
typedef struct bufq_s {
    bufq_elem_t *first; /**< @brief The first queue element */
    bufq_elem_t *last; /**< @brief The last queue element */
    int read_idx; /**< @brief The read index within the first element */
    int write_idx; /**< @brief The write index within the last element */
} bufq_t;


/**
 * @brief Pushes a buffer to the queue.
 *
 * This is to push a buffer to the end of a queue. It adjusts the
 * queue's pointers and should run in O(1) time. Takes ownership
 * of the buffer, so don't free the buffer after enqueueing it.
 *
 * As an aside, don't push a buffer twice unless you're sure you're not
 * going to free it twice.
 * @param queue The queue to insert into.
 * @param buf The buffer to insert into the queue. Don't free this after
 *            insertion. It's expected that this buffer is malloc'd (or NULL).
 * @param buflen The size of the buffer.
 * @return TPX_SUCCESS on success, TPX_FAILURE in case allocating the element
 *         fails.
 */
tpx_err_t enqueue(bufq_t *queue, unsigned char *buf, size_t buflen);

/**
 * @brief Takes the first buffer from the queue and deletes it.
 *
 * This gets a buffer from the start of a queue in O(1) time and
 * removes it. The buffer is now nonexistent within the queue and so
 * now the pointer belongs to the user who grabs it.
 * @param[in/out] queue The queue to dequeue from.
 * @param[out] buf A pointer to fill in with the queue element's buffer pointer.
 *             If buf is NULL, just delete the first element of the set.
 * @return TPX_SUCCESS on success, TPX_FAILURE on failure, and TPX_EMPTY on an
 *         empty queue.
 */
tpx_err_t dequeue(bufq_t *queue, unsigned char **buf, size_t *buflen);

/**
 * @brief Gets the first buffer from the queue without deleting it.
 *
 * This gets a buffer from the start of a queue in O(1) time.
 * @param[in/out] queue The queue to get the first element of.
 * @param[out] buf A pointer to fill in with the queue element's buffer pointer.
 *             NULL is a valid buffer pointer.
 * @return TPX_SUCCESS on success, TPX_FAILURE on failure, and TPX_EMPTY on an
 *         empty queue.
 */
tpx_err_t queue_peek(bufq_t *queue, unsigned char **buf, size_t *buflen);

/**
 * @brief Peeks the last buffer from the queue.
 *
 * This gets a buffer from the end of a queue in O(1) time (we maintain a pointer
 * to the last element of the queue).
 * @param[in/out] queue The queue to get the last element of.
 * @param[out] buf A pointer to fill in with the queue element's buffer pointer.
 *             NULL is a valid buffer pointer.
 * @return TPX_SUCCESS on success, TPX_FAILURE on failure, and TPX_EMPTY on an
 *         empty queue.
 */
tpx_err_t queue_peek_last(bufq_t *queue, unsigned char **buf, size_t *buflen);

/** @brief Check if the queue is empty */
int queue_empty(bufq_t *queue);

/** @brief Allocate a new empty queue */
bufq_t *queue_new();
/** @brief Free the queue properly */
void queue_free(bufq_t *queue);


#endif
