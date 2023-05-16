#include "config.h"
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>

#include "auth.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("usage: %s <config_file> <OIDC token> <command>\n", argv[0]);
        exit(1);
    }
    int res = parse_config(argv[1], &config);
    if (res == 1) {
        printf("cannot parse config file\n");
        exit(1);
    }

    oidc_token_content_t token_info;
    res = verify_token(argv[2], &token_info);
    cJSON_Delete(config.parsed_object);
    if (res == 1) {
        printf("cannot verify token\n");
        exit(1);
    }
    char *uname = malloc(sizeof(char) * 4);
    strncpy(uname, token_info.user, 3);
    uname[3] = 0;
    struct passwd *pwd = getpwnam(uname);
    if (pwd == NULL) {
        printf("Cannot find UID for name %s\n", uname);
        free(uname);
        exit(1);
    }
    printf("Executing command \"%s\" as %s(%d)\n", argv[3], uname, pwd->pw_uid);
    free(token_info.user);
    free(uname);
    setuid(pwd->pw_uid);
    system(argv[3]);
}
