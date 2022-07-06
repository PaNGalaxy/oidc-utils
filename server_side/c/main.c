#include "config.h"
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[]) {
    json_config_t config;
    int res = parse_config("/Users/35y/projects/ndip/oidc-pam/server_side/oidc-pam.json", &config);
    printf("res: %d\n",res);
    if (res ==1) {
        exit(1);
    }
    printf("%s %s %s %d\n",config.client_id,config.client_secret,config.introspection_url,config.enable_2fa);

}
