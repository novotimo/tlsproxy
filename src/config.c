#include "config.h"

#include <stdio.h>

#include "errors.h"

/**
 * Verify config rules that can't be verified by YAML parser
 */
int tpx_validate_conf_l(const tpx_listen_conf_t *config) {
    // If changing the logic here, make sure to also change the logic in
    // handle_reload in main.c
    if (!config->cert_chain && !config->cacerts) {
        fprintf(stderr, "Config error: either 'cert-chain' or 'cacerts' must be"
                " provided.\n");
        return TPX_FAILURE;
    } else if (config->cert_chain && (config->cacerts || config->servcert)) {
        fprintf(stderr, "Config error: 'cert-chain' can't be used "
                "together with 'cacerts' or 'servcert'.\n");
        return TPX_FAILURE;
    } else if (config->cacerts && !config->servcert) {
        fprintf(stderr, "Config error: 'servcert' must be specified if "
                "'cacerts' is.\n");
        return TPX_FAILURE;
    } else if (config->listen_port > UINT16_MAX) {
        fprintf(stderr, "Config error: 'listen-port' must be a valid port "
                "number\n");
        return TPX_FAILURE;
    } else if (config->target_port > UINT16_MAX) {
        fprintf(stderr, "Config error: 'target-port' must be a valid port "
                "number\n");
        return TPX_FAILURE;
    }
    return TPX_SUCCESS;
}

int tpx_validate_conf(const tpx_config_t *config) {
    for (int i=0; i<config->listeners_count; ++i)
        if (tpx_validate_conf_l(&config->listeners[i]) == TPX_FAILURE)
            return TPX_FAILURE;
    return TPX_SUCCESS;
}
