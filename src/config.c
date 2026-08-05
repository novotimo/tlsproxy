#include "config.h"

#include <stdio.h>

#include "errors.h"

// This is arbitrary for now, but we need to make sure people don't
// fork bomb themselves
#define TPX_WORKERS_MAX 128

/**
 * Verify config rules that can't be verified by YAML parser
 */
int tpx_validate_conf_l(const tpx_listen_conf_t *config) {
    // If changing the logic here, make sure to also change the logic in
    // handle_reload in main.c
    if (!config->cert_chain && !config->cacerts) {
        fprintf(stderr, "Config error in listener %s: either 'cert-chain' or "
                "'cacerts' must be provided.\n", config->name);
        return TPX_FAILURE;
    } else if (config->cert_chain && (config->cacerts || config->servcert)) {
        fprintf(stderr, "Config error in listener %s: 'cert-chain' can't be "
                "used together with 'cacerts' or 'servcert'.\n", config->name);
        return TPX_FAILURE;
    } else if (config->cacerts && !config->servcert) {
        fprintf(stderr, "Config error in listener %s: 'servcert' must be "
                "specified if 'cacerts' is.\n", config->name);
        return TPX_FAILURE;
    } else if (config->listen_port > UINT16_MAX) {
        fprintf(stderr, "Config error in listener %s: 'listen-port' must be a "
                "valid port number\n", config->name);
        return TPX_FAILURE;
    } else if (config->target_port > UINT16_MAX) {
        fprintf(stderr, "Config error in listener %s: 'target-port' must be a "
                "valid port number\n", config->name);
        return TPX_FAILURE;
    } else if (config->tcp_keepidle > INT_MAX) {
        fprintf(stderr, "Config error in listener %s: 'tcp-keepidle' must be "
                "less than %d\n", config->name, INT_MAX);
        return TPX_FAILURE;
    } else if (config->tcp_keepintvl > INT_MAX) {
        fprintf(stderr, "Config error in listener %s: 'tcp-keepintvl' must be "
                "less than %d\n", config->name, INT_MAX);
        return TPX_FAILURE;
    } else if (config->tcp_keepcnt > INT_MAX) {
        fprintf(stderr, "Config error in listener %s: 'tcp-keepcnt' must be "
                "less than %d\n", config->name, INT_MAX);
        return TPX_FAILURE;
    }
    return TPX_SUCCESS;
}

int tpx_validate_conf(const tpx_config_t *config) {
    if (config->listeners_count < 1) {
        fprintf(stderr, "Config error: No listeners provided\n");
        return TPX_FAILURE;
    }

    if (config->nworkers == 0) {
        fprintf(stderr, "Config error: nworkers must be greater than zero\n");
        return TPX_FAILURE;
    } else if (config->nworkers > TPX_WORKERS_MAX) {
        fprintf(stderr, "Config error: nworkers must be at most %u\n",
               TPX_WORKERS_MAX);
        return TPX_FAILURE;
    }
    for (size_t i=0; i<config->listeners_count; ++i)
        if (tpx_validate_conf_l(&config->listeners[i]) == TPX_FAILURE)
            return TPX_FAILURE;
    return TPX_SUCCESS;
}
