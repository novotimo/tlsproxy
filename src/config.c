#include "config.h"

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>

#include "errors.h"

#define TPX_STR_(x) #x
#define TPX_STR(x) TPX_STR_(x)

// This is arbitrary for now, but we need to make sure people don't
// fork bomb themselves
#define TPX_WORKERS_MAX 128

#define TPX_LISTENER_NAME_TRUNCATE_AT 128
#define TPX_CONFIG_ERR_MSG "Config error in listener "
#define TPX_CONFIG_ERR_MSGLEN (sizeof(TPX_CONFIG_ERR_MSG)-1)


static inline void
write_err(int *logfd, const char *err_type, const char *err_msg) {
    if (logfd)
        log_system_err_m_ex(*logfd, LL_ERROR, err_type, err_msg);
    else
        fprintf(stderr, "%s: %s\n", err_type, err_msg);
}


/**
 * Verify config rules that can't be verified by YAML parser
 */
int tpx_validate_conf_l(const tpx_listen_conf_t *config, int *logfd) {
    char error_type[TPX_CONFIG_ERR_MSGLEN + TPX_LISTENER_NAME_TRUNCATE_AT + 1];

    // We're purposely truncating the listener's name
    if (snprintf(error_type, sizeof(error_type),
                 TPX_CONFIG_ERR_MSG "%s", config->name) < 0) {
        write_err(logfd, "Config error", "Couldn't format the listener name");
        return TPX_FAILURE;
    }

    if (!config->cert_chain && !config->cacerts) {
        write_err(logfd, error_type,
                  "Either 'cert-chain' or 'cacerts' must be provided");
        return TPX_FAILURE;
    } else if (config->cert_chain && (config->cacerts || config->servcert)) {
        write_err(logfd, error_type,
                  "'cert-chain' can't be used together with 'cacerts' or"
                  " 'servcert'");
        return TPX_FAILURE;
    } else if (config->cacerts && !config->servcert) {
        write_err(logfd, error_type,
                  "'servcert' must be specified if 'cacerts' is");
        return TPX_FAILURE;
    } else if (config->listen_port > UINT16_MAX || config->listen_port == 0) {
        write_err(logfd, error_type,
                  "'listen-port' must be a valid port number between 1 and "
                  "65535 inclusive");
        return TPX_FAILURE;
    } else if (config->target_port > UINT16_MAX || config->target_port == 0) {
        write_err(logfd, error_type,
                  "'target-port' must be a valid port number between 1 and "
                  "65535 inclusive");
        return TPX_FAILURE;
    } else if (config->tcp_keepidle > TPX_MAX_TCP_KEEPIDLE) {
        write_err(logfd, error_type,
                  "'tcp-keepidle' must be at most "
                  TPX_STR(TPX_MAX_TCP_KEEPIDLE));
        return TPX_FAILURE;
    } else if (config->tcp_keepintvl > TPX_MAX_TCP_KEEPINTVL) {
        write_err(logfd, error_type,
                  "'tcp-keepintvl' must be at most "
                  TPX_STR(TPX_MAX_TCP_KEEPINTVL));
        return TPX_FAILURE;
    } else if (config->tcp_keepcnt > TPX_MAX_TCP_KEEPCNT) {
        write_err(logfd, error_type,
                  "'tcp-keepcnt' must be at most "
                  TPX_STR(TPX_MAX_TCP_KEEPCNT));
        return TPX_FAILURE;
    }
    return TPX_SUCCESS;
}

int tpx_validate_conf(const tpx_config_t *config, int *logfd) {
    const char err_type[] = "Config error";

    if (config->listeners_count < 1) {
        write_err(logfd, err_type, "No listeners provided");
        return TPX_FAILURE;
    }

    if (config->nworkers == 0) {
        write_err(logfd, err_type, "'nworkers' must be greater than 0");
        return TPX_FAILURE;
    } else if (config->nworkers > TPX_WORKERS_MAX) {
        write_err(logfd, err_type,
                  "'nworkers' must be at most " TPX_STR(TPX_WORKERS_MAX));
        return TPX_FAILURE;
    }
    for (size_t i=0; i<config->listeners_count; ++i)
        if (tpx_validate_conf_l(&config->listeners[i], logfd) == TPX_FAILURE)
            return TPX_FAILURE;
    return TPX_SUCCESS;
}


void check_keyfiles(int logfd, const tpx_config_t *config) {
    struct stat statbuf;
    size_t nlisteners = config->listeners_count;

    static const char errmsg_fmt[] = "Keyfile '%s' has permissions that are "
        "too permissive. Permissions of 0600 are recommended";

    // stat() refuses a pathname of PATH_MAX bytes or more with ENAMETOOLONG,
    // so a path that gets past it is at most PATH_MAX-1 bytes
    char errmsg[sizeof(errmsg_fmt) - 2 + PATH_MAX];

    for (size_t i=0; i<nlisteners; ++i) {
        // We ignore stat errors here, since OpenSSL will give us
        // errors anyway
        if (stat(config->listeners[i].servkey, &statbuf) == 0) {
            if (statbuf.st_mode & (S_IRWXG | S_IRWXO)) {
                snprintf(errmsg, sizeof(errmsg), errmsg_fmt,
                         config->listeners[i].servkey);

                log_system_err_m_ex(logfd, LL_WARN,
                                    "Keyfile permissions wrong", errmsg);
                fprintf(stderr, "%s\n", errmsg);
            }
        }
    }
}
