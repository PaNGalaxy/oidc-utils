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
    buffer = malloc (length+1);
    if (!buffer) {
        return 1;
    }
    fread (buffer, 1, length, f);
    fclose (f);
    buffer[length]=0;
    
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

    const cJSON *auth = cJSON_GetObjectItemCaseSensitive(config_json, "auth");
    config->n_auth = cJSON_GetArraySize(auth);
    const cJSON *auth_itr = NULL;
    int i = 0;
    config->jwks_url = malloc(sizeof(char*)*config->n_auth);
    config->name_field = malloc(sizeof(char*)*config->n_auth);
    config->name_separator = malloc(sizeof(char*)*config->n_auth);

    cJSON_ArrayForEach(auth_itr, auth)
    {
        const cJSON *jwks_url = cJSON_GetObjectItemCaseSensitive(auth_itr, "jwks_url");
        const cJSON *name_field = (cJSON_GetObjectItemCaseSensitive(auth_itr, "name_field"));
        const cJSON *name_separator = (cJSON_GetObjectItemCaseSensitive(auth_itr, "name_separator"));
        if (!cJSON_IsString(jwks_url) || (jwks_url->valuestring == NULL) ||
            !cJSON_IsString(name_field) || (name_field->valuestring == NULL) ||
            !cJSON_IsString(name_separator) || (name_separator->valuestring == NULL))
        {
            free(buffer);
            return 1;
        }
        config->jwks_url[i] = jwks_url->valuestring;
        config->name_field[i] = name_field->valuestring;
        config->name_separator[i] = name_separator->valuestring;
        i++;
    }
    const cJSON *check_2fa = cJSON_GetObjectItemCaseSensitive(config_json, "check_2fa");
    const cJSON *enable_log = cJSON_GetObjectItemCaseSensitive(config_json, "enable_log");
    const cJSON *log_file = cJSON_GetObjectItemCaseSensitive(config_json, "log_file");
    const cJSON *cache_folder = cJSON_GetObjectItemCaseSensitive(config_json, "cache_folder");

    if (!cJSON_IsBool(check_2fa) || !cJSON_IsBool(enable_log)
    || !cJSON_IsString(cache_folder) || (cache_folder->valuestring == NULL))
    {
        free(buffer);
        return 1;
    }


    config->enable_2fa = cJSON_IsFalse(check_2fa)?0:1;
    config->enable_log = cJSON_IsFalse(enable_log)?0:1;
    config->log_file = log_file->valuestring;
    config->cache_folder = cache_folder->valuestring;

    config->parsed_object = config_json;
    free(buffer);

    return 0;
}
