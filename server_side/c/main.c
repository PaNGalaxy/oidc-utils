#include "config.h"
#include <stdio.h>
#include <stdlib.h>

#include "auth.h"

int main(int argc, char *argv[]) {
    printf("args: %s %s\n", argv[1], argv[2]);

    int res = parse_config(argv[1], &config);
    printf("res: %d\n",res);
    if (res ==1) {
        exit(1);
    }
    printf("%s %s %d\n",config.jwks_url,config.log_file,config.enable_2fa);

    oidc_token_content_t token_info;
    res = verify_token(argv[2], &token_info);
    printf("user: %s\n",token_info.user);
    if (res == 1) {
        exit(1);
    }
    cJSON_Delete(config.parsed_object);
    free(token_info.user);
}
