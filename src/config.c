#include "config.h"

#include <stdio.h>

#include "errors.h"

/**
 * Verify config rules that can't be verified by YAML parser
 */
int tpx_validate_conf(struct tpx_config *config) {
    if (!config->cert_chain && !config->cacerts) {
        fprintf(stderr, "Config error: either 'cert-chain' or 'cacerts' must be"
                " provided.\n");
        return TPX_FAILURE;
    }
    if (config->cert_chain && (config->cacerts || config->servcert)) {
        fprintf(stderr, "Config error: 'cert-chain' can't be used "
                "together with 'cacerts' or 'servcert'.\n");
        return TPX_FAILURE;
    }

    if (config->cacerts && !config->servcert) {
        fprintf(stderr, "Config error: 'servcert' must be specified if "
                "'cacerts' is.\n");
        return TPX_FAILURE;
    }

    return TPX_SUCCESS;
}
