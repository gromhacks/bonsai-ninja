#include "auth_service.h"
#include <cstdlib>
#include <sqlite3.h>

namespace micro {

std::string verify_token(const std::string& token) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("auth.db", &db);
    std::string query = "SELECT user_id FROM tokens WHERE token = '" + token + "'";
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr); // sink: SQL injection
    std::string user_id;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    sqlite3_close(db);
    return user_id;
}

void run_admin_command(const std::string& user_id, const std::string& cmd) {
    if (!user_id.empty()) {
        std::string full_cmd = "notify-admin " + cmd;
        system(full_cmd.c_str()); // sink: command injection
    }
}

}
