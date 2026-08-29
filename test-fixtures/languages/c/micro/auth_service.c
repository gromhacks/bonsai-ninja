#include "auth_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

char *verify_token(const char *token) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char query[256];
    sqlite3_open("auth.db", &db);
    sprintf(query, "SELECT user_id FROM tokens WHERE token = '%s'", token);
    sqlite3_prepare_v2(db, query, -1, &stmt, NULL); /* sink: SQL injection */
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return strdup((const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_close(db);
    return NULL;
}

void run_admin_command(const char *user_id, const char *cmd) {
    if (user_id != NULL) {
        char buf[512];
        sprintf(buf, "notify-admin %s", cmd);
        system(buf); /* sink: command injection */
    }
}
