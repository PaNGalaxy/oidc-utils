#ifndef OIDC_PAM_CONFIG_H
#define OIDC_PAM_CONFIG_H

#include "cjwt/cJSON.h"

typedef struct json_config_t
{
    int n_auth;
    const char **jwks_url;
    const char **name_field;
    const char **name_separator;
    int enable_2fa;
    int enable_log;
    const char *log_file;
    const char *cache_folder;
    cJSON *parsed_object;
} json_config_t;

extern json_config_t config;


int parse_config(const char* fname, json_config_t* config);

#endif //OIDC_PAM_CONFIG_H
