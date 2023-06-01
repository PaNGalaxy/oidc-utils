#include "config.h"
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/fcntl.h>

#include "auth.h"

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("usage: %s <config_file> <OIDC token> <mode> <path|command>\n", argv[0]);
        exit(1);
    }
    int res = parse_config(argv[1], &config);
    if (res != 0) {
        printf("cannot parse config file\n");
        exit(1);
    }

    oidc_token_content_t token_info;
    res = verify_token(argv[2], &token_info);
    cJSON_Delete(config.parsed_object);
    if (res != 0) {
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
    free(token_info.user);
    free(uname);
    res = setuid(pwd->pw_uid);
    if (res != 0) {
        printf("cannot set uid\n");
        exit(1);
    }
    if (strcmp(argv[3],"-c") == 0) {
        return system(argv[4]);
    } else if (strcmp(argv[3],"-f") == 0) {
        int fd = open(argv[4], O_RDONLY);
        if (fd == -1) {
            printf("cannot open file %s\n", argv[4]);
            exit(1);
        }

        char buf[1024];
        int buflen;
        while((buflen = read(fd, buf, 1024)) > 0)
        {
            write(1, buf, buflen);
        }
        close(fd);

    } else {
        printf("wrong mode %s\n",argv[3]);
        exit(1);
    }

}
