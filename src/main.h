#ifndef __TLSPROXY_MAIN_H
#define __TLSPROXY_MAIN_H


/*********************************************
 * Defines
 ********************************************/

#define TPX_FAILURE 0
#define TPX_SUCCESS 1
#define TPX_AGAIN   2

// Number stolen from nginx
#define TPX_MAX_EVENTS 100
#define TPX_NET_BUFSIZE 16384


/*********************************************
 * Structs
 ********************************************/

typedef struct connection_s {
    int fd;

    //void (*handle_read)(
} connection_t;


/*********************************************
 * Prototypes
 ********************************************/

void echo_respond(int fd);

int init_worker();
//int init_cycle();
//int do_cycle();


#endif
