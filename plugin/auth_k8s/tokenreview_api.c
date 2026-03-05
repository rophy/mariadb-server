/*
 * Kubernetes TokenReview API Client Implementation
 *
 * Uses MariaDB's JSON service (service_json.h) for parsing and
 * libcurl for HTTP communication.
 */

#include "tokenreview_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <mysql/service_json.h>

/* Default configuration values */
#define DEFAULT_API_SERVER "https://kubernetes.default.svc"
#define DEFAULT_CA_CERT "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
#define DEFAULT_TOKEN_PATH "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define DEFAULT_TIMEOUT 10

/* Buffer for response data */
typedef struct {
    char *data;
    size_t size;
} response_buffer_t;

/**
 * Callback function for libcurl to write response data
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp)
{
    size_t realsize = size * nmemb;
    response_buffer_t *buffer = (response_buffer_t *)userp;
    char *ptr;

    ptr = realloc(buffer->data, buffer->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "K8s Auth: Out of memory for response buffer\n");
        return 0;
    }

    buffer->data = ptr;
    memcpy(&(buffer->data[buffer->size]), contents, realsize);
    buffer->size += realsize;
    buffer->data[buffer->size] = '\0';

    return realsize;
}

/**
 * Read file contents into a string
 */
static char* read_file(const char *path)
{
    FILE *fp;
    long size;
    char *content;
    size_t nread;

    fp = fopen(path, "r");
    if (!fp)
        return NULL;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) { /* Max 1MB */
        fclose(fp);
        return NULL;
    }

    content = malloc(size + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }

    nread = fread(content, 1, size, fp);
    content[nread] = '\0';
    fclose(fp);

    return content;
}

/**
 * Build the TokenReview API request JSON using snprintf.
 *
 * The token value is JSON-escaped using the json_escape_string service.
 */
static char* build_token_review_request(const char *token)
{
    size_t token_len = strlen(token);
    /* Escaped token can be at most 6x the original (all \uXXXX) */
    size_t escaped_max = token_len * 6 + 1;
    char *escaped_token;
    int escaped_len;
    const char *tmpl;
    size_t request_size;
    char *request;

    escaped_token = malloc(escaped_max);
    if (!escaped_token)
        return NULL;

    escaped_len = json_escape_string(token, token + token_len,
                                     escaped_token,
                                     escaped_token + escaped_max);
    if (escaped_len < 0) {
        free(escaped_token);
        return NULL;
    }

    /* Fixed template + escaped token */
    tmpl = "{\"apiVersion\":\"authentication.k8s.io/v1\","
           "\"kind\":\"TokenReview\","
           "\"spec\":{\"token\":\"%.*s\"}}";

    request_size = strlen(tmpl) + escaped_len + 1;
    request = malloc(request_size);
    if (!request) {
        free(escaped_token);
        return NULL;
    }

    snprintf(request, request_size, tmpl, escaped_len, escaped_token);
    free(escaped_token);
    return request;
}

void k8s_config_init_default(k8s_config_t *config)
{
    config->api_server_url = DEFAULT_API_SERVER;
    config->ca_cert_path = DEFAULT_CA_CERT;
    config->token_path = DEFAULT_TOKEN_PATH;
    config->timeout_seconds = DEFAULT_TIMEOUT;
}

int k8s_parse_username(const char *username, char *ns, size_t namespace_len,
                       char *service_account, size_t sa_len)
{
    char temp_ns[K8S_MAX_NAMESPACE_LEN + 1];
    char temp_sa[K8S_MAX_NAME_LEN + 1];
    int matched;

    if (!username || !ns || !service_account)
        return 0;

    /* Expected format: system:serviceaccount:namespace:serviceaccount-name */
    matched = sscanf(username,
                     "system:serviceaccount:%253[^:]:%253s",
                     temp_ns, temp_sa);
    if (matched != 2)
        return 0;

    strncpy(ns, temp_ns, namespace_len - 1);
    ns[namespace_len - 1] = '\0';

    strncpy(service_account, temp_sa, sa_len - 1);
    service_account[sa_len - 1] = '\0';

    return 1;
}

/**
 * Parse TokenReview response JSON using MariaDB's JSON service.
 *
 * Expected structure:
 * {
 *   "status": {
 *     "authenticated": true,
 *     "user": {
 *       "username": "system:serviceaccount:ns:sa",
 *       "uid": "..."
 *     }
 *   }
 * }
 */
static int parse_token_review_response(const char *response, size_t response_len,
                                       k8s_token_info_t *info)
{
    const char *status_js;
    int status_len;
    const char *val;
    int val_len;
    enum json_types auth_type;
    const char *user_js;
    int user_len;
    size_t copy_len;

    /* Get "status" object */
    if (json_get_object_key(response, response + response_len,
                            "status", &status_js, &status_len) != JSV_OBJECT) {
        fprintf(stderr, "K8s Auth: No 'status' field in TokenReview response\n");
        return 0;
    }

    /* Get "status.authenticated" */
    auth_type = json_get_object_key(status_js, status_js + status_len,
                                    "authenticated", &val, &val_len);
    if (auth_type == JSV_TRUE) {
        info->authenticated = 1;
    } else if (auth_type == JSV_FALSE) {
        info->authenticated = 0;
        fprintf(stderr, "K8s Auth: Token authentication failed\n");
        return 0;
    } else {
        fprintf(stderr,
                "K8s Auth: No 'authenticated' field in TokenReview response\n");
        return 0;
    }

    /* Get "status.user" object */
    if (json_get_object_key(status_js, status_js + status_len,
                            "user", &user_js, &user_len) != JSV_OBJECT) {
        fprintf(stderr, "K8s Auth: No 'user' field in TokenReview response\n");
        return 0;
    }

    /* Get "status.user.username" */
    if (json_get_object_key(user_js, user_js + user_len,
                            "username", &val, &val_len) == JSV_STRING) {
        copy_len = (size_t)val_len < sizeof(info->username) - 1
                   ? (size_t)val_len : sizeof(info->username) - 1;
        memcpy(info->username, val, copy_len);
        info->username[copy_len] = '\0';

        /* Parse namespace and service account from username */
        if (!k8s_parse_username(info->username,
                                info->namespace, sizeof(info->namespace),
                                info->service_account,
                                sizeof(info->service_account))) {
            fprintf(stderr, "K8s Auth: Failed to parse username: %s\n",
                    info->username);
            return 0;
        }

        fprintf(stderr, "K8s Auth: Token validated successfully\n");
        fprintf(stderr, "K8s Auth: Username: %s\n", info->username);
        fprintf(stderr, "K8s Auth: Namespace: %s\n", info->namespace);
        fprintf(stderr, "K8s Auth: ServiceAccount: %s\n",
                info->service_account);
    }

    /* Get "status.user.uid" */
    if (json_get_object_key(user_js, user_js + user_len,
                            "uid", &val, &val_len) == JSV_STRING) {
        copy_len = (size_t)val_len < sizeof(info->uid) - 1
                   ? (size_t)val_len : sizeof(info->uid) - 1;
        memcpy(info->uid, val, copy_len);
        info->uid[copy_len] = '\0';
    }

    return 1;
}

int k8s_validate_token(const char *token, k8s_token_info_t *info,
                       const k8s_config_t *config)
{
    CURL *curl = NULL;
    CURLcode res;
    int result = 0;
    response_buffer_t response = {NULL, 0};
    struct curl_slist *headers = NULL;
    char *service_account_token = NULL;
    char *request_json = NULL;
    k8s_config_t default_config;
    char auth_header[4096];
    char api_url[1024];
    long http_code = 0;

    /* Input validation */
    if (!token || !info) {
        fprintf(stderr, "K8s Auth: Invalid input parameters\n");
        return 0;
    }

    /* Initialize info structure */
    memset(info, 0, sizeof(k8s_token_info_t));

    /* Use default config if not provided */
    if (!config) {
        k8s_config_init_default(&default_config);
        config = &default_config;
    }

    /* Initialize libcurl */
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "K8s Auth: Failed to initialize curl\n");
        return 0;
    }

    /* Build TokenReview request JSON */
    request_json = build_token_review_request(token);
    if (!request_json) {
        fprintf(stderr, "K8s Auth: Failed to build TokenReview request\n");
        goto cleanup;
    }

    /* Read service account token for authentication */
    service_account_token = read_file(config->token_path);
    if (!service_account_token) {
        fprintf(stderr,
                "K8s Auth: Failed to read service account token from %s\n",
                config->token_path);
        goto cleanup;
    }

    /* Set up HTTP headers */
    headers = curl_slist_append(headers, "Content-Type: application/json");

    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
             service_account_token);
    headers = curl_slist_append(headers, auth_header);

    /* Build TokenReview API URL */
    snprintf(api_url, sizeof(api_url),
             "%s/apis/authentication.k8s.io/v1/tokenreviews",
             config->api_server_url);

    /* Configure curl options */
    curl_easy_setopt(curl, CURLOPT_URL, api_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout_seconds);

    /* SSL/TLS configuration */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, config->ca_cert_path);

    /* Perform the request */
    fprintf(stderr, "K8s Auth: Calling TokenReview API at %s\n", api_url);
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "K8s Auth: TokenReview API call failed: %s\n",
                curl_easy_strerror(res));
        goto cleanup;
    }

    /* Check HTTP response code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 201 && http_code != 200) {
        fprintf(stderr, "K8s Auth: TokenReview API returned HTTP %ld\n",
                http_code);
        if (response.data)
            fprintf(stderr, "K8s Auth: Response: %s\n", response.data);
        goto cleanup;
    }

    /* Parse the response using MariaDB JSON service */
    if (!parse_token_review_response(response.data, response.size, info))
        goto cleanup;

    info->validated_at = time(NULL);
    result = 1;

cleanup:
    if (curl)
        curl_easy_cleanup(curl);
    if (headers)
        curl_slist_free_all(headers);
    if (response.data)
        free(response.data);
    if (service_account_token)
        free(service_account_token);
    if (request_json)
        free(request_json);

    return result;
}
