#ifndef __TLSPROXY_LOGMACROS_H
#define __TLSPROXY_LOGMACROS_H


#include "shmem.h"


#define LOG_MSG(LEVEL, ...) \
    (g_shmem->logger.enabled && g_shmem->logger.loglevel >= LEVEL) ? \
    log_msg(&g_shmem->logger, __VA_ARGS__) : (void)0
#define LOG_OSSL(LEVEL, DESC) \
    (g_shmem->logger.enabled && g_shmem->logger.loglevel >= LEVEL) ? \
    log_ossl(&g_shmem->logger, DESC) : (void)0
#define LOG_PERROR(LEVEL, DESC) \
    (g_shmem->logger.enabled && g_shmem->logger.loglevel >= LEVEL) ? \
    log_msg(&g_shmem->logger, "%s: %s", DESC, strerror(errno)) : (void)0
    

#endif
