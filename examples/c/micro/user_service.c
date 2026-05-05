#include "user_service.h"
#include "auth_service.h"
#include <stdlib.h>
#include <string.h>

UserInfo *get_user(const char *token) {
    char *user_id = verify_token(token);
    if (user_id == NULL) {
        return NULL;
    }
    UserInfo *info = malloc(sizeof(UserInfo));
    info->id = user_id;
    info->token = strdup(token);
    return info;
}

char *update_user(const char *token, const char *action) {
    char *user_id = verify_token(token);
    if (user_id != NULL) {
        run_admin_command(user_id, action);
    }
    return user_id;
}
