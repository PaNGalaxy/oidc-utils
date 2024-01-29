#include "config.h"
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <openssl/sha.h>
#include <time.h>

#include "auth.h"

char *copy_until_separator(const char *src, const char *separator) {
    if (src == NULL) {
        return NULL;
    }
    const char *separator_ptr = (separator && separator[0] != '\0') ? strstr(src, separator) : NULL;
    size_t length_to_copy = (separator_ptr != NULL) ? (size_t) (separator_ptr - src) : strlen(src);

    char *dest = malloc(length_to_copy + 1);
    if (dest == NULL) {
        return NULL;
    }

    strncpy(dest, src, length_to_copy);
    dest[length_to_copy] = '\0';

    return dest;
}

char* remove_quotes(const char *str) {
    int len = strlen(str);
    char *result;
    if (len >= 2 && str[0] == '\'' && str[len - 1] == '\'') {
         result = (char *)malloc(len - 1);
        strncpy(result, str + 1, len - 2);
        result[len - 2] = '\0';
        return result;
    } else {
        result = (char *)malloc(len+1);
        strcpy(result, str);
    }
    return result;
}

void sha256_string(const char *string, char outputBuffer[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

void get_token_file_path(const char *token, char *token_file_path, int len) {
    char token_file[65];
    sha256_string(token, token_file);
    snprintf(token_file_path, len, "%s/%s", config.cache_folder, token_file);
}

int token_from_file(const char *token_file_path, char *username) {
    long expirationTime = 0;
    time_t currentTime;

    FILE *file;
    file = fopen(token_file_path, "r");
    if (file != NULL) {
        if (fscanf(file, "%s %ld", username, &expirationTime) != 2) {
            fprintf(stderr, "Error reading from file\n");
            fclose(file);
            return 1;
        }
        fclose(file);
    }
    currentTime = time(NULL);

    return currentTime > expirationTime;
}

struct passwd *pwd_from_token(const char *token, const char *token_file_path) {
    oidc_token_content_t token_info;
    int auth;
    int res;
    for (auth = 0; auth < config.n_auth; auth++) {
        res = verify_token(token, &token_info, auth);
        if (res == 0) {
            break;
        }
    }
    if (res != 0) {
        printf("cannot verify token\n");
        exit(1);
    }
    char *uname = copy_until_separator(token_info.user, config.name_separator[auth]);
    struct passwd *pwd = getpwnam(uname);
    if (pwd == NULL) {
        printf("Cannot find UID for name %s\n", uname);
        free(uname);
        exit(1);
    }
    FILE *file = fopen(token_file_path, "w");
    fprintf(file, "%s %lld\n", uname, token_info.exp);
    fclose(file);
    free(token_info.user);
    free(uname);
    return pwd;
}

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
    config.log_file="system";

    // get uid from token, verify token if not in cache
    char token_file_path[4056];
    get_token_file_path(argv[2], token_file_path, sizeof(token_file_path));
    char username[50];
    struct passwd *pwd;
    if (token_from_file(token_file_path, username) == 0) {
        // token in cache and not expired
        pwd = getpwnam(username);
    } else {
        pwd = pwd_from_token(argv[2], token_file_path);
    }

    res = setuid(pwd->pw_uid);
    if (res != 0) {
        printf("cannot set uid\n");
        exit(1);
    }
    if (strcmp(argv[3], "-c") == 0) {
        char* command = remove_quotes(argv[4]);
        int res = system(command);
        free(command);
        exit(res == 0 ? 0 : 1);
    } else if (strcmp(argv[3], "-f") == 0) {
        int fd = open(argv[4], O_RDONLY);
        if (fd == -1) {
            printf("cannot open file %s\n", argv[4]);
            exit(1);
        }

        char buf[1024];
        int buflen;
        while ((buflen = read(fd, buf, sizeof(buf))) > 0) {
            write(1, buf, buflen);
        }
        close(fd);

    } else {
        printf("wrong mode %s\n", argv[3]);
        exit(1);
    }

    cJSON_Delete(config.parsed_object);
    free (config.jwks_url);
    free (config.name_field);
    free (config.name_separator);
}
