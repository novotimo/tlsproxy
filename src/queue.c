#include "queue.h"

#include <stdio.h>

#include "errors.h"
#include "logging.h"



tpx_err_t check_consistency(bufq_t *queue);


tpx_err_t enqueue(bufq_t *queue, unsigned char *buf, size_t buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;
    
    bufq_elem_t *elem = malloc(sizeof(bufq_elem_t));
    if (!elem) {
        log_system_err(LL_ERROR, "Couldn't allocate memory for buffer queue"
                       " element", TPX_ERR_ERRNO);
        return TPX_FAILURE;
    }
    elem->next = NULL;
    elem->buf = buf;
    elem->buflen = buflen;

    if (!queue->first && !queue->last) {
        queue->first = queue->last = elem;
        queue->write_idx = queue->read_idx = 0;
    } else {
        queue->last->next = elem;
        queue->last = elem;
    }

    return TPX_SUCCESS;
}

tpx_err_t dequeue(bufq_t *queue, unsigned char **buf, size_t *buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;

    if (queue->first == NULL && queue->last == NULL)
        return TPX_EMPTY;
    
    bufq_elem_t *elem = queue->first;
    queue->first = elem->next;
    if (!queue->first) {
        queue->last = NULL;
        queue->write_idx = 0;
    }
    
    if (buf)
        *buf = elem->buf;
    if (buflen)
        *buflen = elem->buflen;
    free(elem);
    
    return TPX_SUCCESS;
}

tpx_err_t queue_peek(bufq_t *queue, unsigned char **buf, size_t *buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;

    if (queue->first == NULL && queue->last == NULL)
        return TPX_EMPTY;
    
    const bufq_elem_t *elem = queue->first;
    if (buf)
        *buf = elem->buf;
    if (buflen)
        *buflen = elem->buflen;
    
    return TPX_SUCCESS;
}

tpx_err_t queue_peek_last(bufq_t *queue, unsigned char **buf, size_t *buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;

    if (queue->first == NULL && queue->last == NULL)
        return TPX_EMPTY;
    
    const bufq_elem_t *elem = queue->last;
    if (buf)
        *buf = elem->buf;
    if (buflen)
        *buflen = elem->buflen;
    
    return TPX_SUCCESS;
}

int queue_empty(bufq_t *queue) {
    return queue->first == NULL;
}

tpx_err_t check_consistency(bufq_t *queue) {
    if (!queue) {
        log_system_err(LL_ERROR, "Queue is NULL", TPX_ERR_PLAIN);
        return TPX_FAILURE;
    }
    if (queue->first && !queue->last) {
        log_system_err(LL_ERROR,
                       "Queue corrupt: NULL last element on non-empty queue",
                       TPX_ERR_PLAIN);
        return TPX_FAILURE;
    } else if (!queue->first && queue->last) {
        log_system_err(LL_ERROR,
                       "Queue corrupt: NULL first element on non-empty queue",
                       TPX_ERR_PLAIN);
        return TPX_FAILURE;
    };
    return TPX_SUCCESS;
}

bufq_t *queue_new(void) {
    bufq_t *q = calloc(1, sizeof(bufq_t));
    if (!q) {
        log_system_err(LL_ERROR,
                       "Couldn't allocate memory for new buffer queue",
                       TPX_ERR_ERRNO);
        return NULL;
    }
    return q;
}

void queue_free(bufq_t *queue) {
    if (queue) {
        // If the queue is broken, we take the memory leak in exchange for
        // no double frees
        if (check_consistency(queue) != TPX_SUCCESS) {
            return free(queue);
        }

        unsigned char *buf;
        while(!queue_empty(queue)) {
            dequeue(queue, &buf, NULL);
            if (buf) free(buf);
        }
        free(queue);
    }
}
