#ifndef __TLSPROXY_CONFIG_H
#define __TLSPROXY_CONFIG_H

#include <cyaml/cyaml.h>

typedef struct tpx_config {
    const char *target_ip;
    unsigned int target_port;

    const char *listen_ip;
    unsigned int listen_port;

    const char **cacerts;
    unsigned int cacerts_count;
    const char *cert_chain;
    const char *servcert;
    const char *servkey;
    const char *servkeypass;
} tpx_config_t;


static const cyaml_schema_value_t cacert_entry = {
    CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t top_mapping_schema[] = {
    CYAML_FIELD_STRING_PTR(
        "target-ip", CYAML_FLAG_POINTER, tpx_config_t, target_ip,
        0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT(
        "target-port", CYAML_FLAG_DEFAULT, tpx_config_t, target_port),
    
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

int tpx_validate_conf(tpx_config_t *config);

#endif
