#include "queue.h"

#include <stdio.h>

#include "errors.h"


tpx_err_t check_consistency(bufq_t *queue);


tpx_err_t enqueue(bufq_t *queue, unsigned char *buf, size_t buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;
    
    bufq_elem_t *elem = malloc(sizeof(bufq_elem_t));
    if (!elem) {
        perror("enqueue: malloc");
        return TPX_FAILURE;
    }
    elem->next = NULL;
    elem->buf = buf;
    elem->buflen = buflen;

    if (!queue->first && !queue->last) {
        queue->first = queue->last = elem;
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
        queue->read_idx = -1;
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
        fprintf(stderr, "Queue is NULL\n");
        return TPX_FAILURE;
    }
    if (queue->first && !queue->last) {
        fprintf(stderr,
                "Queue corrupt: NULL last element on non-empty queue\n");
        return TPX_FAILURE;
    } else if (!queue->first && queue->last) {
        fprintf(stderr,
                "Queue corrupt: NULL first element on non-empty queue\n");
        return TPX_FAILURE;
    };
    return TPX_SUCCESS;
}

bufq_t *queue_new() {
    bufq_t *q = calloc(1, sizeof(bufq_t));
    if (!q) {
        perror("queue_new: calloc");
        return NULL;
    }
    q->write_idx = -1;
    return q;
}

void queue_free(bufq_t *queue) {
    if (queue) {
        unsigned char *buf;
        while(!queue_empty(queue)) {
            dequeue(queue, &buf, NULL);
            if (buf) free(buf);
        }
        free(queue);
    }
}
