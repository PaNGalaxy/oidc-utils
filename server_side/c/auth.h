#ifndef OIDC_PAM_AUTH_H
#define OIDC_PAM_AUTH_H

#include "config.h"

typedef struct oidc_token_content_t
{
    const char *user;
    const char *session_attribute;
    int active;
    cJSON *parsed_object;
} oidc_token_content_t;

int introspect_token(const char* token, oidc_token_content_t *token_info);


#endif //OIDC_PAM_AUTH_H
