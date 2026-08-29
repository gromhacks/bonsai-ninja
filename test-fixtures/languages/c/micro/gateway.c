#include "gateway.h"
#include "user_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_request(const char *query_string) {
    char token[128];
    char action[128];
    sscanf(query_string, "token=%127[^&]&action=%127s", token, action); /* source: user input */

    UserInfo *user = get_user(token);         /* flows to SQL injection */
    char *result = update_user(token, action); /* flows to command injection */

    printf("{\"user\": \"%s\", \"result\": \"%s\"}\n",
           user ? user->id : "null", result ? result : "null");
    free(user);
    free(result);
}
