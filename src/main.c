#include "main.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "config.h"
#include "connection.h"
#include "errors.h"

static const cyaml_config_t cyaml_config = {
	.log_fn = cyaml_log,
	.mem_fn = cyaml_mem,
	.log_level = CYAML_LOG_WARNING,
};

void usage(char *progname) {
    fprintf(stderr, "Usage: %s <config.yml>\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    printf("TLS Proxy starting\n");

    if (argc != 2)
        usage(argv[0]);

    char *config_file = argv[1];
    struct tpx_config *tpx_config;

    cyaml_err_t conf_err =
        cyaml_load_file(config_file, &cyaml_config, &top_schema,
                        (cyaml_data_t **)&tpx_config, NULL);
    if (conf_err != CYAML_OK) {
        errx(EXIT_FAILURE, "%s", cyaml_strerror(conf_err));
    } else if (tpx_validate_conf(tpx_config) != TPX_SUCCESS) {
        errx(EXIT_FAILURE, "Config file '%s' failed verification", config_file);
    }

    struct epoll_event events[TPX_MAX_EVENTS];

    int epollfd = epoll_create1(0);
    if (epollfd == -1)
        err(EXIT_FAILURE, "epoll_create1");

    connection_t *listener = tpx_create_listener(NULL, 9090);
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = listener;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->fd, &ev) == -1)
        err(EXIT_FAILURE, "epoll_ctl: listen_sock");

    int nfds;
    tpx_err_t handle_err = TPX_SUCCESS;
    for (;;) {
        nfds = epoll_wait(epollfd, events, TPX_MAX_EVENTS, -1);
        for (size_t n=0; n < nfds; ++n) {
            handle_err = tpx_handle_all(events[n].data.ptr,
                                        epollfd, events[n].events);
            if (handle_err != TPX_SUCCESS)
                tpx_conn_close(events[n].data.ptr, epollfd);
        }
    }
    
    return(EXIT_SUCCESS);
}
