#ifndef __TLSPROXY_TIMEUTILS_H
#define __TLSPROXY_TIMEUTILS_H

#include <stdint.h>


uint64_t gettime();
int timeout_expired(uint64_t expiring);


#endif
