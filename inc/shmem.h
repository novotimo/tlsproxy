#ifndef __TLSPROXY_SHMEM_H
#define __TLSPROXY_SHMEM_H


#include "logging.h"


typedef struct shared_s {
    logger_t logger;
} shared_t;


extern shared_t *g_shmem;


#endif
