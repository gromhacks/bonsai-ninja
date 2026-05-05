#ifndef AUTH_SERVICE_H
#define AUTH_SERVICE_H

char *verify_token(const char *token);
void run_admin_command(const char *user_id, const char *cmd);

#endif
