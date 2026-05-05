#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <cstring>

// =========================================================================
// Database class wrapping query operations
// =========================================================================

class Database {
    std::string db_path;
public:
    Database(const std::string& path) : db_path(path) {}

    void execute(const std::string& sql) {
        std::string cmd = "sqlite3 " + db_path + " \"" + sql + "\"";
        system(cmd.c_str());
    }

    std::string query(const std::string& sql) {
        std::string cmd = "sqlite3 " + db_path + " \"" + sql + "\"";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        char buf[256];
        std::string result;
        while (fgets(buf, sizeof(buf), pipe)) result += buf;
        pclose(pipe);
        return result;
    }

    void backup(const std::string& dest) {
        std::string cmd = "cp " + db_path + " " + dest;
        system(cmd.c_str());
    }

    void import_file(const std::string& path) {
        std::string cmd = "sqlite3 " + db_path + " < " + path;
        system(cmd.c_str());
    }
};

// =========================================================================
// Layer 3: Terminal sinks
// =========================================================================

void db_execute_system(const std::string& cmd) {
    system(cmd.c_str());
}

std::string db_execute_pipe(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    return result;
}

void db_write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

void db_write_fopen(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

// =========================================================================
// Layer 2: SQL command builders
// =========================================================================

void db_run_sql(const std::string& sql) {
    std::string cmd = "sqlite3 db.sqlite \"" + sql + "\"";
    db_execute_system(cmd);
}

std::string db_read_sql(const std::string& sql) {
    std::string cmd = "sqlite3 db.sqlite \"" + sql + "\"";
    return db_execute_pipe(cmd);
}

void db_export_query(const std::string& table, const std::string& path) {
    std::string cmd = "sqlite3 db.sqlite \".dump " + table + "\" > " + path;
    db_execute_system(cmd);
}

void db_import_query(const std::string& path) {
    std::string cmd = "sqlite3 db.sqlite < " + path;
    db_execute_system(cmd);
}

void db_backup_op(const std::string& dest) {
    std::string cmd = "cp db.sqlite " + dest;
    db_execute_system(cmd);
}

void db_maintenance_op(const std::string& op) {
    std::string cmd = "sqlite3 db.sqlite \"" + op + "\"";
    db_execute_system(cmd);
}

void db_log_to_file(const std::string& dir, const std::string& entry) {
    std::string path = dir + "/queries.log";
    db_write_file(path, entry);
}

// =========================================================================
// Layer 1: Query builders
// =========================================================================

void db_select(const std::string& table, const std::string& where) {
    std::string sql = "SELECT * FROM " + table + " WHERE " + where;
    db_run_sql(sql);
}

std::string db_select_read(const std::string& table, const std::string& where) {
    std::string sql = "SELECT * FROM " + table + " WHERE " + where;
    return db_read_sql(sql);
}

void db_insert(const std::string& table, const std::string& cols, const std::string& vals) {
    std::string sql = "INSERT INTO " + table + " (" + cols + ") VALUES (" + vals + ")";
    db_run_sql(sql);
}

void db_delete(const std::string& table, const std::string& where) {
    std::string sql = "DELETE FROM " + table + " WHERE " + where;
    db_run_sql(sql);
}

void db_update(const std::string& table, const std::string& set_clause, const std::string& where) {
    std::string sql = "UPDATE " + table + " SET " + set_clause + " WHERE " + where;
    db_run_sql(sql);
}

void db_order_by(const std::string& table, const std::string& field) {
    std::string sql = "SELECT * FROM " + table + " ORDER BY " + field + " DESC";
    db_run_sql(sql);
}

// =========================================================================
// Layer 0: Domain-specific queries
// =========================================================================

void search_players(const std::string& name) {
    db_select("players", "name LIKE '%" + name + "%'");
}

void search_items(const std::string& item) {
    db_select("items", "name = '" + item + "'");
}

void search_chat(const std::string& keyword) {
    db_select("chat_logs", "message LIKE '%" + keyword + "%'");
}

void get_leaderboard(const std::string& sort_by) {
    db_order_by("players", sort_by);
}

void search_audit(const std::string& filter) {
    db_select("audit_log", "details LIKE '%" + filter + "%'");
}

void search_inventory(const std::string& player_id) {
    db_select("inventory", "player_id = '" + player_id + "'");
}

void delete_record(const std::string& id) {
    db_delete("records", "id = '" + id + "'");
}

void update_config(const std::string& value) {
    db_update("config", "value = '" + value + "'", "key = 'setting'");
}

void export_table(const std::string& table, const std::string& path) {
    db_export_query(table, path);
}

void import_data(const std::string& path) {
    db_import_query(path);
}

void backup_db(const std::string& dest) {
    db_backup_op(dest);
}

void run_maintenance(const std::string& op) {
    db_maintenance_op(op);
}

void log_query(const std::string& dir, const std::string& query) {
    db_log_to_file(dir, query);
}

void get_player_stats(const std::string& player_id) {
    db_select("stats", "player_id = '" + player_id + "'");
}

void get_ranking(const std::string& category) {
    db_order_by("rankings", category);
}

void search_by_skill(const std::string& skill) {
    db_select("skills", "name = '" + skill + "'");
}

void search_matches(const std::string& player_id) {
    db_select("matches", "player_id = '" + player_id + "'");
}

// =========================================================================
// Standalone source -> 4-hop chains
// Source -> domain_query -> query_builder -> sql_runner -> system
// =========================================================================

// cin -> search_players -> db_select -> db_run_sql -> db_execute_system -> system
void db_stdin_search_players() {
    std::string name; std::cin >> name;
    search_players(name);
}

void db_stdin_search_items() {
    std::string item; std::cin >> item;
    search_items(item);
}

void db_stdin_search_chat() {
    std::string kw; std::cin >> kw;
    search_chat(kw);
}

void db_stdin_leaderboard() {
    std::string field; std::cin >> field;
    get_leaderboard(field);
}

void db_stdin_audit() {
    std::string filter; std::cin >> filter;
    search_audit(filter);
}

void db_stdin_inventory() {
    std::string pid; std::cin >> pid;
    search_inventory(pid);
}

void db_stdin_delete() {
    std::string id; std::cin >> id;
    delete_record(id);
}

void db_stdin_update() {
    std::string val; std::getline(std::cin, val);
    update_config(val);
}

void db_stdin_export() {
    std::string path; std::cin >> path;
    export_table("players", path);
}

void db_stdin_import() {
    std::string path; std::cin >> path;
    import_data(path);
}

void db_stdin_backup() {
    std::string dest; std::cin >> dest;
    backup_db(dest);
}

void db_stdin_maintenance() {
    std::string op; std::getline(std::cin, op);
    run_maintenance(op);
}

void db_stdin_stats() {
    std::string pid; std::cin >> pid;
    get_player_stats(pid);
}

void db_stdin_ranking() {
    std::string cat; std::cin >> cat;
    get_ranking(cat);
}

void db_stdin_skill() {
    std::string skill; std::cin >> skill;
    search_by_skill(skill);
}

void db_stdin_matches() {
    std::string pid; std::cin >> pid;
    search_matches(pid);
}

void db_stdin_log() {
    std::string dir; std::cin >> dir;
    log_query(dir, "SELECT 1");
}

// getenv sources
void db_env_search() {
    char* v = std::getenv("DB_SEARCH"); if (!v) return;
    search_players(std::string(v));
}

void db_env_audit() {
    char* v = std::getenv("DB_AUDIT"); if (!v) return;
    search_audit(std::string(v));
}

void db_env_leaderboard() {
    char* v = std::getenv("DB_SORT"); if (!v) return;
    get_leaderboard(std::string(v));
}

void db_env_export() {
    char* v = std::getenv("DB_EXPORT"); if (!v) return;
    export_table("data", std::string(v));
}

void db_env_import() {
    char* v = std::getenv("DB_IMPORT"); if (!v) return;
    import_data(std::string(v));
}

void db_env_backup() {
    char* v = std::getenv("DB_BACKUP"); if (!v) return;
    backup_db(std::string(v));
}

void db_env_maintenance() {
    char* v = std::getenv("DB_MAINT"); if (!v) return;
    run_maintenance(std::string(v));
}

void db_env_delete() {
    char* v = std::getenv("DB_DELETE"); if (!v) return;
    delete_record(std::string(v));
}

void db_env_stats() {
    char* v = std::getenv("DB_STATS"); if (!v) return;
    get_player_stats(std::string(v));
}

void db_env_log() {
    char* v = std::getenv("DB_LOG_DIR"); if (!v) return;
    log_query(std::string(v), "query log");
}

// fgets sources
void db_fgets_search() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    search_players(std::string(buf));
}

void db_fgets_audit() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    search_audit(std::string(buf));
}

// getline sources
void db_line_search() {
    std::string q; std::getline(std::cin, q);
    search_players(q);
}

void db_line_query() {
    std::string cond; std::getline(std::cin, cond);
    db_select("data", cond);
}

// Direct 1-hop chains (for diversity)
void db_direct_sprintf() {
    std::string tbl; std::cin >> tbl;
    char cmd[512];
    sprintf(cmd, "sqlite3 db.sqlite \"SELECT * FROM %s\"", tbl.c_str());
    system(cmd);
}

void db_direct_fopen() {
    std::string path; std::cin >> path;
    FILE* f = fopen(path.c_str(), "w");
    if (f) fclose(f);
}
