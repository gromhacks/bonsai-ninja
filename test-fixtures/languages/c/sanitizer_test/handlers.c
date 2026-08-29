/* C sanitizer-fixture — parallel handlers per sink family. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/* --- SQL injection -------------------------------------------------- */

void sql_raw(sqlite3 *db, const char *user_id) {
    sqlite3_stmt *stmt;
    char q[256];
    snprintf(q, sizeof q, "SELECT * FROM users WHERE id = '%s'", user_id);
    sqlite3_prepare_v2(db, q, -1, &stmt, NULL);
}

void sql_safe(sqlite3 *db, const char *user_id) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, user_id, -1, SQLITE_TRANSIENT);
}

/* --- Path buffer safety --------------------------------------------- */

void path_raw(const char *name, char *out, size_t outsz) {
    strcat(out, name);  /* unbounded — caller must have sized out. */
}

void path_safe(const char *name, char *out, size_t outsz) {
    strlcpy(out, name, outsz);  /* bounded by outsz. */
}
