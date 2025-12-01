#ifndef __TLSPROXY_MAIN_H
#define __TLSPROXY_MAIN_H

#include "connection.h"
#include "errors.h"
#include "queue.h"


/*********************************************
 * Defines
 ********************************************/

// Number stolen from nginx
#define TPX_MAX_EVENTS 100

/*********************************************
 * Prototypes
 ********************************************/

void echo_respond(int fd);

//int init_worker();
//int init_cycle();
//int do_cycle();


#endif
