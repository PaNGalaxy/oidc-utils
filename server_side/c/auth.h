#ifndef OIDC_PAM_AUTH_H
#define OIDC_PAM_AUTH_H

#include "config.h"

typedef struct MemoryStruct {
    char *memory;
    size_t size;
} memory_struct;

typedef struct oidc_token_content_t
{
    char *user;
    // const char *session_attribute;
    // int active;
} oidc_token_content_t;

int verify_token(const char* token, oidc_token_content_t *token_info);

cJSON* fetch_jwks();

char *load_cert(const char* x509);


#endif //OIDC_PAM_AUTH_H
