#include "auth.h"

#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include "cjwt/cJSON.h"
#include "cjwt/cjwt.h"
#include "cjwt/base64.h"
#include "log.h"

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    memory_struct *mem = (memory_struct *) userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        /* out of memory! */
        logit("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

unsigned char* base64_urlsafe_decode(const char *input, int length, int *out_length) {
    // Convert base64 URL-safe to base64 standard
    char *converted = malloc(length + 2); // extra bytes for potential padding
    strcpy(converted, input);
    for (int i = 0; i < length; ++i) {
        if (converted[i] == '-') converted[i] = '+';
        if (converted[i] == '_') converted[i] = '/';
    }
    // Add necessary padding
    while (strlen(converted) % 4) {
        strcat(converted, "=");
    }

    // Decode base64 standard
    BIO *bio, *b64;
    unsigned char *buffer = malloc(length); // decoded length will be <= encoded length
    bio = BIO_new_mem_buf(converted, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
    *out_length = BIO_read(bio, buffer, strlen(converted));
    BIO_free_all(bio);

    free(converted);
    return buffer;
}


int verify_token(const char *token, oidc_token_content_t *token_info, int auth_number) {
    
    cJSON *keyset_json = fetch_jwks(auth_number);

    if (keyset_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            logit("Error before: %s\n", error_ptr);
        }
        return 1;
    }

    // Get Key Id from token
    cjwt_header_t *jwt_header = NULL;

    cjwt_code_t cjwt_return_value = cjwt_get_header(token, strlen(token), OPT_ALLOW_ANY_TIME, &jwt_header);

    if(CJWTE_OK != cjwt_return_value) {
        logit("Could not get KID: %s\n", token);
        cjwt_header_destroy(jwt_header);
        return 1;
    }

    const char *token_kid = jwt_header->kid;

    // Search for correct key
    const cJSON *keyset = cJSON_GetObjectItemCaseSensitive(keyset_json, "keys");

    const  char *n = NULL;
    const  char *e = NULL;

    const cJSON *key_itr = NULL;
    const cJSON *kid = NULL;    
    cJSON_ArrayForEach(key_itr, keyset)
    {
        kid = cJSON_GetObjectItemCaseSensitive(key_itr, "kid");
        if (strcmp(kid->valuestring, token_kid) == 0)
        {
            n = (cJSON_GetObjectItemCaseSensitive(key_itr, "n")->valuestring); // Modulus
            e = (cJSON_GetObjectItemCaseSensitive(key_itr, "e")->valuestring); // Exponent
        }
    }

    cjwt_header_destroy(jwt_header);

    // Handle not finding the correct key
    if (!n || !e) {
        logit("Could not find correct key in keyset. Token: %s\n", token);
        return 1;
    }

    int n_length, e_length;
    unsigned char *n_bytes = base64_urlsafe_decode(n, strlen(n), &n_length);
    unsigned char *e_bytes = base64_urlsafe_decode(e, strlen(e), &e_length);
    BIGNUM *n_bn = BN_bin2bn(n_bytes, n_length, NULL);
    BIGNUM *e_bn = BN_bin2bn(e_bytes, e_length, NULL);

    // Create RSA key
    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, n_bn, e_bn, NULL);
    BIO *pem_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(pem_bio, rsa);

    char *loaded_cert;
    BIO_get_mem_data(pem_bio, &loaded_cert);

    // Actually validate token now
    cjwt_t *jwt = NULL;
    cjwt_return_value = cjwt_decode(token, strlen(token), 0, (uint8_t *)loaded_cert, strlen(loaded_cert), time(NULL), 0, &jwt);
    free(loaded_cert);
    if (CJWTE_OK != cjwt_return_value) {
        logit("There was an issue while decoding token: %d\n", cjwt_return_value);
        cjwt_destroy(jwt);
        return 1;
    }

    const cJSON *user = cJSON_GetObjectItemCaseSensitive(jwt->private_claims, config.name_field[auth_number]);
    token_info->exp = *(jwt->exp);

    if (!cJSON_IsString(user) || (user->valuestring == NULL)) {
        logit("Could not find %s claim.\n",config.name_field[auth_number]);
        cjwt_destroy(jwt);
        return 1;
    }
    // Set token info user
    token_info->user = malloc(strlen(user->valuestring));
    strcpy(token_info->user, user->valuestring);

    cJSON_Delete(keyset_json);
    cjwt_destroy(jwt);

    return 0;
}

cJSON* fetch_jwks(int auth_number) {
    memory_struct mem;

    mem.memory = malloc(1);  /* will be grown as needed by realloc above */
    mem.size = 0;    /* no data at this point */

    // Fetch Jwks to decrypt token
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    long http_code = 0;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, config.jwks_url[auth_number]);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &mem);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            logit("curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
            return NULL;
        } else {
            curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    if (http_code != 200) {
        free(mem.memory);
        return NULL;
    }

    cJSON *keyset_json = cJSON_Parse(mem.memory);
    free(mem.memory);
    return keyset_json;
}