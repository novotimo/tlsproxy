#include "queue.h"

#include <stdio.h>

#include "errors.h"

int check_consistency(queue_t *queue);


int tpx_enqueue(queue_t *queue, unsigned char *buf, size_t buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;
    
    queue_elem_t *elem = malloc(sizeof(queue_elem_t));
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

int tpx_dequeue(queue_t *queue, unsigned char **buf, size_t *buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;

    if (queue->first == NULL && queue->last == NULL)
        return TPX_EMPTY;
    
    queue_elem_t *elem = queue->first;
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

int tpx_queue_peek(queue_t *queue, unsigned char **buf, size_t *buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;

    if (queue->first == NULL && queue->last == NULL)
        return TPX_EMPTY;
    
    queue_elem_t *elem = queue->first;
    if (buf)
        *buf = elem->buf;
    if (buflen)
        *buflen = elem->buflen;
    
    return TPX_SUCCESS;
}

int tpx_queue_peek_last(queue_t *queue, unsigned char **buf, size_t *buflen) {
    if (check_consistency(queue) != TPX_SUCCESS)
        return TPX_FAILURE;

    if (queue->first == NULL && queue->last == NULL)
        return TPX_EMPTY;
    
    queue_elem_t *elem = queue->last;
    if (buf)
        *buf = elem->buf;
    if (buflen)
        *buflen = elem->buflen;
    
    return TPX_SUCCESS;
}

int tpx_queue_empty(queue_t *queue) {
    return queue->first == NULL;
}

int check_consistency(queue_t *queue) {
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

queue_t *tpx_queue_new() {
    queue_t *q = calloc(1, sizeof(queue_t));
    q->write_idx = -1;
    return q;
}

void tpx_queue_free(queue_t *queue) {
    if (queue) {
        unsigned char *buf;
        while(!tpx_queue_empty(queue)) {
            tpx_dequeue(queue, &buf, NULL);
            if (buf) free(buf);
        }
        free(queue);
    }
}
