/*
 * MariaDB Kubernetes ServiceAccount Authentication Plugin - Server Side
 *
 * Validates ServiceAccount tokens using Kubernetes TokenReview API.
 */

#include <mysql/plugin_auth.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "tokenreview_api.h"

#define PLUGIN_VERSION 0x0100

/* Plugin system variables */
static char *api_url;
static char *ca_path;
static char *token_path;
static int timeout;

static MYSQL_SYSVAR_STR(api_url, api_url,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Kubernetes API server URL",
  NULL, NULL, "https://kubernetes.default.svc");

static MYSQL_SYSVAR_STR(ca_path, ca_path,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path to Kubernetes CA certificate",
  NULL, NULL, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");

static MYSQL_SYSVAR_STR(token_path, token_path,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "Path to ServiceAccount token file for API authentication",
  NULL, NULL, "/var/run/secrets/kubernetes.io/serviceaccount/token");

static MYSQL_SYSVAR_INT(timeout, timeout,
  PLUGIN_VAR_RQCMDARG,
  "Timeout in seconds for Kubernetes API requests",
  NULL, NULL, 10, 1, 300, 1);

static struct st_mysql_sys_var *auth_k8s_sysvars[] = {
    MYSQL_SYSVAR(api_url),
    MYSQL_SYSVAR(ca_path),
    MYSQL_SYSVAR(token_path),
    MYSQL_SYSVAR(timeout),
    NULL
};

/*
 * Server authentication function
 */
static int auth_k8s_server(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
    unsigned char *packet;
    int packet_len;
    char *token;
    char token_preview[50];
    int preview_len;
    k8s_config_t config;
    k8s_token_info_t token_info;
    int valid;
    char expected_user[K8S_MAX_NAMESPACE_LEN + K8S_MAX_NAME_LEN + 2];

    /* Send a request to the client for the ServiceAccount token */
    if (vio->write_packet(vio, (unsigned char *)"", 0))
    {
        return CR_ERROR;
    }

    /* Read the token from the client */
    packet_len = vio->read_packet(vio, &packet);
    if (packet_len < 0)
    {
        return CR_ERROR;
    }

    /* Check if token was provided */
    if (packet_len == 0)
    {
        fprintf(stderr, "K8s Auth: No token provided\n");
        info->password_used = PASSWORD_USED_NO;
        return CR_ERROR;
    }

    info->password_used = PASSWORD_USED_YES;

    /* Null-terminate the token string */
    token = malloc(packet_len + 1);
    if (!token) {
        fprintf(stderr, "K8s Auth: Memory allocation failed\n");
        return CR_ERROR;
    }
    memcpy(token, packet, packet_len);
    token[packet_len] = '\0';

    /* Log token info (preview only for security) */
    memset(token_preview, 0, sizeof(token_preview));
    preview_len = packet_len < 40 ? packet_len : 40;
    memcpy(token_preview, token, preview_len);
    fprintf(stderr, "K8s Auth: Received token (length=%d, preview=%.40s...)\n",
            packet_len, token_preview);
    fprintf(stderr, "K8s Auth: Authenticating user '%s'\n", info->user_name);

    /* Build config from system variables */
    config.api_server_url = api_url;
    config.ca_cert_path = ca_path;
    config.token_path = token_path;
    config.timeout_seconds = timeout;

    /* Validate token with Kubernetes TokenReview API */
    valid = k8s_validate_token(token, &token_info, &config);

    free(token);

    if (!valid || !token_info.authenticated) {
        fprintf(stderr, "K8s Auth: Token validation failed\n");
        return CR_ERROR;
    }

    /* Build expected username from MariaDB user: namespace/serviceaccount */
    snprintf(expected_user, sizeof(expected_user), "%s/%s",
             token_info.namespace, token_info.service_account);

    /* Verify that the MariaDB username matches the ServiceAccount */
    if (strcmp(info->user_name, expected_user) != 0) {
        fprintf(stderr, "K8s Auth: User mismatch. Expected '%s', got '%s'\n",
                expected_user, info->user_name);
        fprintf(stderr, "K8s Auth: Token is for %s/%s\n",
                token_info.namespace, token_info.service_account);
        return CR_ERROR;
    }

    fprintf(stderr, "K8s Auth: Authentication successful for %s/%s\n",
            token_info.namespace, token_info.service_account);
    return CR_OK;
}

/*
 * Plugin descriptor structure
 */
static struct st_mysql_auth auth_k8s_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,
    "mysql_clear_password",  /* Client plugin name - use built-in clear password plugin */
    auth_k8s_server,         /* Server authentication function */
    NULL,                    /* Generate auth string (not used) */
    NULL                     /* Validate auth string (not used) */
};

/*
 * Plugin declaration
 */
mysql_declare_plugin(auth_k8s)
{
    MYSQL_AUTHENTICATION_PLUGIN,
    &auth_k8s_handler,
    "auth_k8s",
    "MariaDB K8s Auth Plugin Contributors",
    "Kubernetes ServiceAccount Authentication with TokenReview",
    PLUGIN_LICENSE_GPL,
    NULL,                    /* Plugin init */
    NULL,                    /* Plugin deinit */
    PLUGIN_VERSION,
    NULL,                    /* Status variables */
    auth_k8s_sysvars,        /* System variables */
    NULL,                    /* Config options */
    0                        /* Flags */
}
mysql_declare_plugin_end;
