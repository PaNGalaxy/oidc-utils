#include <stdio.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>

#include "config.h"
#include "auth.h"
#include "log.h"

/* expected hooks */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

int conversation(pam_handle_t *pamh, const char *prompt, char **response) {
    struct pam_message msg;
    struct pam_conv *conv;
    struct pam_response *pResp;
    const struct pam_message *pMsg = &msg;
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt;
    int rc = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (rc != PAM_SUCCESS) {
        logstr("error in pam_get_item\n");
        return rc;
    }
    rc = conv->conv(1, (const struct pam_message **) &pMsg, &pResp, conv->appdata_ptr);
    if (rc != PAM_SUCCESS || pResp == NULL) {
        logstr("error in conv\n");
        return PAM_CONV_ERR;
    }
    if (pResp[0].resp == NULL) {
        logstr("empty response\n");
        free(pResp);
        return PAM_AUTH_ERR;
    }

    strcpy(*response, pResp[0].resp);
    free(pResp[0].resp);
    pResp[0].resp = NULL;
    free(pResp);
    return 0;
}

int get_access_token(pam_handle_t *pamh, int use_first_pass, char **access_token) {
    if (use_first_pass) {
        const char *saved_token;
        pam_get_authtok(pamh, PAM_AUTHTOK, &saved_token, NULL);
        strcpy(*access_token, saved_token);
    } else {
        int res = conversation(pamh, "Passcode or token: ", access_token);
        if (res != 0) {
            logstr("error in getting passcode or token\n");
            return res;
        }
    }
    if (strlen(*access_token) < 20) { // assuming this is a password and should be processed in other module
        pam_set_item(pamh, PAM_AUTHTOK, *access_token);
        return PAM_AUTH_ERR;
    }

    char *next_token_part = (char *) malloc(10000 * sizeof(char));
    int res = conversation(pamh, "Next: ", &next_token_part);
    if (res != 0) {
        logstr("error in getting next token part\n");
        free(next_token_part);
        return res;
    }
    while (strlen(next_token_part) > 0 && strcmp(next_token_part, "token_end") != 0) {
        strcat(*access_token, next_token_part);
        res = conversation(pamh, "Next: ", &next_token_part);
        if (res != 0) {
            logstr("error in getting next token part\n");
            free(next_token_part);
            return res;
        }
    }
    if (strlen(*access_token) == 0) {
        logstr("empty access token\n");
        free(next_token_part);
        return PAM_AUTH_ERR;
    }

    free(next_token_part);
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int res = parse_config(argv[0], &config);
    if (res != 0) {
        logstr("cannot parse config file\n");
        return PAM_AUTH_ERR;
    }

    int use_first_pass = argc == 2 && strcmp(argv[1], "use_first_pass") == 0;
    // get user
    const char *pUsername;
    int retval = pam_get_user(pamh, &pUsername, NULL);
    if (retval != PAM_SUCCESS) {
        logstr("unknown user\n");
        return PAM_USER_UNKNOWN;
    }
    // get token
    char *access_token = (char *) malloc(10000 * sizeof(char));
    retval = get_access_token(pamh, use_first_pass, &access_token);
    if (retval != 0) {
        cJSON_Delete(config.parsed_object);
        free(access_token);
        return retval;
    }

    oidc_token_content_t token_content;
    res = verify_token(access_token, &token_content);
    if (res != 0) {
        logit("error introspecting token: %s\n", access_token);
        cJSON_Delete(config.parsed_object);
        free(access_token);
        return PAM_AUTH_ERR;
    }

    int token_ok = 1;
    if (strncmp(token_content.user, pUsername, 3) != 0) {
        logit("error checking username, token: %s, user: %s\n", access_token, pUsername);
        token_ok = 0;
    }

    ///TODO: Figure out 2fa

    cJSON_Delete(config.parsed_object);

    free(access_token);
    free(token_content.user);

    if (token_ok == 0) {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}