#ifndef __TLSPROXY_QUEUE_H
#define __TLSPROXY_QUEUE_H

#include "errors.h"

/*********************************************
 * Structs
 ********************************************/

/** The buffer queue element */
typedef struct queue_elem_s {
    struct chain_link_s *next;
    unsigned char *buf;
} queue_elem_t;

/** The buffer queue, as simple as it can be */
typedef struct queue_s {
    queue_elem_t *first;
    queue_elem_t *last;
} queue_t;


/*********************************************
 * Prototypes
 ********************************************/

/**
 * @brief Pushes a buffer to the queue.
 *
 * This is to push a buffer to the end of a queue. It adjusts the
 * queue's pointers and should run in O(1) time. Takes ownership
 * of the buffer, so it should not be freed.
 *
 * As an aside, don't push a buffer twice since it will be freed twice.
 * @param[in/out] queue The queue to insert into.
 * @param[in] buf The buffer to insert into the queue. Don't free this after
 *            insertion. It's expected that this buffer is malloc'd (or NULL).
 */
void tpx_enqueue(queue_t *queue, unsigned char *buf);

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
int tpx_dequeue(queue_t *queue, unsigned char **buf);

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
int tpx_peek(queue_t *queue, unsigned char **buf);


#endif
