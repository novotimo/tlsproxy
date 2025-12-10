#ifndef __TLSPROXY_CONFIG_H
#define __TLSPROXY_CONFIG_H

#include <cyaml/cyaml.h>

/** @brief The configuration of the TLS Proxy */
typedef struct tpx_config {
    unsigned int nworkers; /**< @brief The number of worker processes. */
    const char *target_ip; /**< @brief The IP address of the upstream server. */
    unsigned int target_port; /**< @brief The port of the upstream service. */
    unsigned int connect_timeout; /**< @brief The timeout for connecting to
                                   * the backend in milliseconds */

    const char *listen_ip; /**< @brief The local IP address to listen on. */
    unsigned int listen_port; /**< @brief The port to listen on. */

    const char **cacerts; /**< @brief The CA certificates used to verify the
                           * server certificate. */
    unsigned int cacerts_count; /**< @brief The number of CA certificates
                                 * provided */
    const char *cert_chain; /**< @brief A file containing the whole chain from
                             * leaf to root, and it must be in that order. */
    const char *servcert; /**< @brief The server certificate to offer to
                           * clients. */
    const char *servkey; /**< @brief The private key of the server certificate
                          */
    const char *servkeypass; /**< @brief The encryption password for the server
                              * key */
} tpx_config_t;


static const cyaml_schema_value_t cacert_entry = {
    CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t top_mapping_schema[] = {
    CYAML_FIELD_UINT(
        "nworkers", CYAML_FLAG_DEFAULT, tpx_config_t, nworkers),
    CYAML_FIELD_STRING_PTR(
        "target-ip", CYAML_FLAG_POINTER, tpx_config_t, target_ip,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT(
        "target-port", CYAML_FLAG_DEFAULT, tpx_config_t, target_port),
    CYAML_FIELD_UINT(
        "connect-timeout", CYAML_FLAG_DEFAULT, tpx_config_t, connect_timeout),
    
    CYAML_FIELD_STRING_PTR(
        "listen-ip", CYAML_FLAG_POINTER, tpx_config_t, listen_ip,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT(
        "listen-port", CYAML_FLAG_DEFAULT, tpx_config_t, listen_port),

    CYAML_FIELD_SEQUENCE_COUNT(
        "cacerts", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, tpx_config_t,
        cacerts, cacerts_count, &cacert_entry, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR(
        "cert-chain", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, tpx_config_t,
        cert_chain, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR(
        "servcert", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, tpx_config_t, servcert,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR(
        "servkey", CYAML_FLAG_POINTER, tpx_config_t, servkey,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR(
        "servkeypass", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, tpx_config_t,
        servkeypass, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t top_schema = {
    CYAML_VALUE_MAPPING(
        CYAML_FLAG_POINTER, tpx_config_t, top_mapping_schema),
};

/** Validate the configuration file, checking that cacerts and cert-chain
 * aren't both configured together.
 *
 * @param config The configuration object
 * @return Returns TPX_FAILURE on failure and TPX_SUCCESS on success.
 */
int tpx_validate_conf(tpx_config_t *config);

#endif
