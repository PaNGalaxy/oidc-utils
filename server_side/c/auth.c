#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include <curl/curl.h>

#include "json/cJSON.h"

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int introspect_token(const char *token, oidc_token_content_t *token_info) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char data[10000];
    sprintf(data, "token=%s&client_id=%s&"
                  "client_secret=%s", token, config.client_id, config.client_secret);

    chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
    chunk.size = 0;    /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    long http_code = 0;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, config.introspection_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
            return 1;
        } else {
            curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    if (http_code != 200) {
        free(chunk.memory);
        return 1;
    }

    cJSON *token_json = cJSON_Parse(chunk.memory);
    if (token_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        free(chunk.memory);
        return 1;
    }

    const cJSON *user = cJSON_GetObjectItemCaseSensitive(token_json, "preferred_username");
    const cJSON *session_attribute = cJSON_GetObjectItemCaseSensitive(token_json, "session_attribute");
    const cJSON *active = cJSON_GetObjectItemCaseSensitive(token_json, "active");
    if (!cJSON_IsString(user) || (user->valuestring == NULL) ||
        !cJSON_IsBool(active)) {
        free(chunk.memory);
        return 1;
    }
    if (!cJSON_IsString(session_attribute)) {
        token_info->session_attribute = NULL;
    } else {
        token_info->session_attribute = session_attribute->valuestring;
    }

    token_info->user = user->valuestring;
    token_info->active = cJSON_IsFalse(active) ? 0 : 1;
    token_info->parsed_object = token_json;
    free(chunk.memory);

    return 0;
}