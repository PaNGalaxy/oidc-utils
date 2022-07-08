#ifndef OIDC_PAM_CONFIG_H
#define OIDC_PAM_CONFIG_H

#include "json/cJSON.h"

typedef struct json_config_t
{
    const char *client_id;
    const char *client_secret;
    const char *introspection_url;
    int enable_2fa;
    int enable_log;
    const char *log_file;
    cJSON *parsed_object;
} json_config_t;

extern json_config_t config;


int parse_config(const char* fname, json_config_t* config);

#endif //OIDC_PAM_CONFIG_H
