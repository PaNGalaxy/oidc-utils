#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
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

int verify_token(const char *token, oidc_token_content_t *token_info) {
    
    cJSON *keyset_json = fetch_jwks();

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

    const unsigned char *key = NULL;
    const cJSON *key_itr = NULL;
    const cJSON *kid = NULL;    
    cJSON_ArrayForEach(key_itr, keyset)
    {
        kid = cJSON_GetObjectItemCaseSensitive(key_itr, "kid");


        if (strcmp(kid->valuestring, token_kid) == 0)
        {
            key = (cJSON_GetObjectItemCaseSensitive(key_itr, "x5c")->child->valuestring);
        }

    }
    // Free header since it's no longer being used
    cjwt_header_destroy(jwt_header);

    // Handle not finding the correct key
    if (!key) {
        logit("Could not find correct key in keyset. Token: %s\n", token);
        return 1;
    }

    // Load Cert here
    char* loaded_cert = load_cert(key);
    cJSON_Delete(keyset_json);
    if (loaded_cert == NULL) {
        logit("Loaded cert is null. Token: %s\n", token);
        return 1;
    }

    // Actually validate token now
    cjwt_t *jwt = NULL;
    cjwt_return_value = cjwt_decode(token, strlen(token), 0, (uint8_t *)loaded_cert, strlen(loaded_cert), time(NULL), 0, &jwt);
    free(loaded_cert);
    if (CJWTE_OK != cjwt_return_value) {
        logit("There was an issue while decoding token: %d\n", cjwt_return_value);
        cjwt_destroy(jwt);
        return 1;
    }

    const cJSON *user = cJSON_GetObjectItemCaseSensitive(jwt->private_claims, "preferred_username");

    if (!cJSON_IsString(user) || (user->valuestring == NULL)) {
        logit("Could not find 'preferred_username' claim.\n");
        cjwt_destroy(jwt);
        return 1;
    }
    // Set token info user
    token_info->user = malloc(strlen(user->valuestring));
    strcpy(token_info->user, user->valuestring);

    cjwt_destroy(jwt);

    return 0;
}

cJSON* fetch_jwks() {
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
        curl_easy_setopt(curl, CURLOPT_URL, config.jwks_url);
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

char *load_cert(const char* x509) {

    /* ---------------------------------------------------------- *
    * These function calls initialize openssl for correct work.  *
    * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    const char *header = "-----BEGIN CERTIFICATE-----\n";
    const char *footer = "\n-----END CERTIFICATE-----";

    char *x509_formatted = malloc(strlen(x509) + strlen(header) + strlen(footer));
    strcpy(x509_formatted, header);
    strcat(x509_formatted, x509);
    strcat(x509_formatted, footer);

    X509 *cert = NULL;
    BIO *certbio = BIO_new(BIO_s_mem());
    BIO_write(certbio, x509_formatted, strlen(x509_formatted) + 1);
    if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        logit("Error reading cert into memory. x509: %s\n", x509_formatted);
        BIO_free_all(certbio);
        free(x509_formatted);
        return NULL;
    }
    BIO_free_all(certbio);

    free(x509_formatted);

    EVP_PKEY *pkey = NULL;
    if ((pkey = X509_get_pubkey(cert)) == NULL) {
        logit("Error getting public key.\n");
        X509_free(cert);
        return NULL;
    }
    X509_free(cert);
    BIO *keybio = BIO_new(BIO_s_mem());
    if(!PEM_write_bio_PUBKEY(keybio, pkey)) {
        logit("Error writing public key data in PEM format\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }
    char* key_buf = (char*) malloc(EVP_PKEY_bits(pkey) + 1);
    memset(key_buf, 0, EVP_PKEY_bits(pkey) + 1);
    BIO_read(keybio, key_buf, EVP_PKEY_bits(pkey));

    EVP_PKEY_free(pkey);
    BIO_free_all(keybio);

    return key_buf;
}