#ifndef OIDC_PAM_AUTH_H
#define OIDC_PAM_AUTH_H

#include "config.h"
#include <inttypes.h>

typedef struct MemoryStruct {
    char *memory;
    size_t size;
} memory_struct;

typedef struct oidc_token_content_t
{
    char *user;
    int64_t exp;
} oidc_token_content_t;

int verify_token(const char* token, oidc_token_content_t *token_info, int auth_number);

cJSON* fetch_jwks(int auth_number);


#endif //OIDC_PAM_AUTH_H
