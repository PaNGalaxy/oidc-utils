#include <stdio.h>
#include <stdlib.h>


#include "config.h"

json_config_t config;

int parse_config(const char* fname, json_config_t* config) {
    char * buffer = 0;
    long length;
    FILE * f = fopen (fname, "rb");

    if (!f) {
        return 1;
    }
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = malloc (length);
    if (!buffer) {
        return 1;
    }
    fread (buffer, 1, length, f);
    fclose (f);

    cJSON *config_json = cJSON_Parse(buffer);
    if (config_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        free(buffer);
        return 1;
    }

    const cJSON *jwks_url = cJSON_GetObjectItemCaseSensitive(config_json, "jwks_url");
    const cJSON *check_2fa = cJSON_GetObjectItemCaseSensitive(config_json, "check_2fa");
    const cJSON *enable_log = cJSON_GetObjectItemCaseSensitive(config_json, "enable_log");
    const cJSON *log_file = cJSON_GetObjectItemCaseSensitive(config_json, "log_file");

    if (!cJSON_IsString(jwks_url) || (jwks_url->valuestring == NULL) ||
        !cJSON_IsBool(check_2fa) || !cJSON_IsBool(enable_log))
    {
        free(buffer);
        return 1;
    }

    config->jwks_url = jwks_url->valuestring;
    config->enable_2fa = cJSON_IsFalse(check_2fa)?0:1;
    config->enable_log = cJSON_IsFalse(enable_log)?0:1;
    config->log_file = log_file->valuestring;

    config->parsed_object = config_json;
    free(buffer);

    return 0;
}