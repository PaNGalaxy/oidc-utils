#include <stdio.h>
#include <stdlib.h>


#include "config.h"

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


    const cJSON *client_id = cJSON_GetObjectItemCaseSensitive(config_json, "client_id");
    const cJSON *client_secret = cJSON_GetObjectItemCaseSensitive(config_json, "client_secret");
    const cJSON *introspection_url = cJSON_GetObjectItemCaseSensitive(config_json, "introspection_url");
    const cJSON *check_2fa = cJSON_GetObjectItemCaseSensitive(config_json, "check_2fa");
    if (!cJSON_IsString(client_id) || (client_id->valuestring == NULL) ||
        !cJSON_IsString(client_secret) || (client_id->valuestring == NULL) ||
        !cJSON_IsString(introspection_url) || (client_id->valuestring == NULL) ||
        !cJSON_IsBool(check_2fa))
    {
        free(buffer);
        return 1;
    }

    config->client_id = client_id->valuestring;
    config->client_secret = client_secret->valuestring;
    config->introspection_url = introspection_url->valuestring;
    config->enable_2fa = cJSON_IsBool(check_2fa)?0:1;
    config->parsed_object = config_json;
    free(buffer);

    return 0;
}
