#ifndef USER_SERVICE_H
#define USER_SERVICE_H

typedef struct {
    char *id;
    char *token;
} UserInfo;

UserInfo *get_user(const char *token);
char *update_user(const char *token, const char *action);

#endif
