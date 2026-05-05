#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "database.cpp"
#include "utils.cpp"

// =========================================================================
// Layer 3: Terminal sinks
// =========================================================================

void xm_exec_system(const std::string& cmd) {
    system(cmd.c_str());
}

std::string xm_exec_pipe(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    return result;
}

void xm_write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

void xm_write_fopen(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

void xm_copy_buf(char* dest, const char* src) {
    strcpy(dest, src);
}

void xm_format_buf(char* dest, const char* src) {
    sprintf(dest, "xm: %s", src);
}

void xm_exec_binary(const std::string& cmd) {
    execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
}

// =========================================================================
// Layer 2: Command/query builders
// =========================================================================

void xm_run_sql(const std::string& sql) {
    std::string cmd = "sqlite3 db.sqlite \"" + sql + "\"";
    xm_exec_system(cmd);
}

std::string xm_read_sql(const std::string& sql) {
    std::string cmd = "sqlite3 db.sqlite \"" + sql + "\"";
    return xm_exec_pipe(cmd);
}

void xm_run_tool(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    xm_exec_system(cmd);
}

void xm_run_pipe_tool(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    xm_exec_pipe(cmd);
}

void xm_save_to(const std::string& dir, const std::string& name, const std::string& content) {
    std::string path = dir + "/" + name;
    xm_write_file(path, content);
}

void xm_save_fopen(const std::string& dir, const std::string& name, const std::string& content) {
    std::string path = dir + "/" + name;
    xm_write_fopen(path, content);
}

void xm_process_buf(const std::string& data) {
    char buf[32];
    xm_copy_buf(buf, data.c_str());
}

void xm_format_data(const std::string& data) {
    char buf[256];
    xm_format_buf(buf, data.c_str());
}

// =========================================================================
// Layer 1: Domain operations
// =========================================================================

void xm_select_query(const std::string& table, const std::string& where) {
    std::string sql = "SELECT * FROM " + table + " WHERE " + where;
    xm_run_sql(sql);
}

void xm_delete_query(const std::string& table, const std::string& where) {
    std::string sql = "DELETE FROM " + table + " WHERE " + where;
    xm_run_sql(sql);
}

void xm_update_query(const std::string& table, const std::string& set_val,
                      const std::string& where) {
    std::string sql = "UPDATE " + table + " SET " + set_val + " WHERE " + where;
    xm_run_sql(sql);
}

void xm_order_query(const std::string& table, const std::string& field) {
    std::string sql = "SELECT * FROM " + table + " ORDER BY " + field;
    xm_run_sql(sql);
}

void xm_read_query(const std::string& table, const std::string& where) {
    std::string sql = "SELECT * FROM " + table + " WHERE " + where;
    xm_read_sql(sql);
}

void xm_admin_action(const std::string& action) {
    xm_run_tool("admin-tool", action);
    xm_save_to("/var/log/admin", "admin.log", action);
}

void xm_backup_action(const std::string& name) {
    xm_run_tool("tar", "czf /var/backups/" + name + ".tar.gz /var/data/");
    xm_run_pipe_tool("sha256sum", "/var/backups/" + name + ".tar.gz");
}

void xm_download_action(const std::string& url) {
    xm_run_tool("curl", "-sL " + url + " | tar xz");
    xm_save_to("/var/log/downloads", "download.log", url);
}

void xm_script_action(const std::string& script) {
    xm_run_pipe_tool("lua", "/opt/scripts/" + script);
    xm_save_to("/var/log/scripts", "run.log", script);
}

void xm_grep_action(const std::string& pattern) {
    xm_run_pipe_tool("grep", "-r \"" + pattern + "\" /var/log/");
    xm_save_to("/var/log/searches", "grep.log", pattern);
}

void xm_export_action(const std::string& table, const std::string& path) {
    std::string cmd = "sqlite3 db.sqlite \".dump " + table + "\" > " + path;
    xm_exec_system(cmd);
    xm_save_to("/var/log/exports", "export.log", path);
}

void xm_import_action(const std::string& path) {
    std::string cmd = "sqlite3 db.sqlite < " + path;
    xm_exec_system(cmd);
    xm_save_to("/var/log/imports", "import.log", path);
}

void xm_save_report(const std::string& name, const std::string& data) {
    xm_save_to("/var/reports", name, data);
}

void xm_save_config(const std::string& key, const std::string& value) {
    xm_save_to("/var/config", key + ".conf", value);
}

void xm_upload_file(const std::string& name, const std::string& data) {
    xm_save_fopen("/var/uploads", name, data);
}

void xm_check_name(const std::string& name) {
    xm_process_buf(name);
}

void xm_format_log(const std::string& msg) {
    xm_format_data(msg);
}

void xm_exec_user_action(const std::string& cmd) {
    xm_exec_binary(cmd);
}

// =========================================================================
// Layer 0: Source -> 4-5 hop chains
// =========================================================================

// cin sources (5 hops: stdin -> domain_op -> layer1 -> layer2 -> layer3 -> system)
void xm_select_entry() {
    std::string cond; std::cin >> cond;
    xm_select_query("users", "name = '" + cond + "'");
}

void xm_delete_entry() {
    std::string id; std::cin >> id;
    xm_delete_query("records", "id = '" + id + "'");
}

void xm_update_entry() {
    std::string val; std::getline(std::cin, val);
    xm_update_query("config", "value = '" + val + "'", "key = 'setting'");
}

void xm_order_entry() {
    std::string field; std::cin >> field;
    xm_order_query("players", field);
}

void xm_read_query_entry() {
    std::string cond; std::cin >> cond;
    xm_read_query("data", cond);
}

void xm_admin_entry_cmd() {
    std::string action; std::cin >> action;
    xm_admin_action(action);
}

void xm_backup_entry_cmd() {
    std::string name; std::cin >> name;
    xm_backup_action(name);
}

void xm_download_entry_cmd() {
    std::string url; std::cin >> url;
    xm_download_action(url);
}

void xm_script_entry_cmd() {
    std::string script; std::cin >> script;
    xm_script_action(script);
}

void xm_grep_entry_cmd() {
    std::string pat; std::cin >> pat;
    xm_grep_action(pat);
}

void xm_export_entry_cmd() {
    std::string path; std::cin >> path;
    xm_export_action("data", path);
}

void xm_import_entry_cmd() {
    std::string path; std::cin >> path;
    xm_import_action(path);
}

void xm_report_entry() {
    std::string name; std::cin >> name;
    xm_save_report(name, "report content");
}

void xm_config_entry() {
    std::string key; std::cin >> key;
    xm_save_config(key, "value");
}

void xm_upload_entry() {
    std::string name; std::cin >> name;
    xm_upload_file(name, "upload data");
}

void xm_checkname_entry() {
    std::string name; std::cin >> name;
    xm_check_name(name);
}

void xm_formatlog_entry() {
    std::string msg; std::cin >> msg;
    xm_format_log(msg);
}

void xm_exec_entry_cmd() {
    std::string cmd; std::cin >> cmd;
    xm_exec_user_action(cmd);
}

// getenv sources
void xm_env_select() {
    char* v = std::getenv("XM_SELECT"); if (!v) return;
    xm_select_query("data", std::string(v));
}

void xm_env_delete() {
    char* v = std::getenv("XM_DELETE"); if (!v) return;
    xm_delete_query("logs", "id = '" + std::string(v) + "'");
}

void xm_env_admin() {
    char* v = std::getenv("XM_ADMIN"); if (!v) return;
    xm_admin_action(std::string(v));
}

void xm_env_backup() {
    char* v = std::getenv("XM_BACKUP"); if (!v) return;
    xm_backup_action(std::string(v));
}

void xm_env_download() {
    char* v = std::getenv("XM_URL"); if (!v) return;
    xm_download_action(std::string(v));
}

void xm_env_script() {
    char* v = std::getenv("XM_SCRIPT"); if (!v) return;
    xm_script_action(std::string(v));
}

void xm_env_grep() {
    char* v = std::getenv("XM_GREP"); if (!v) return;
    xm_grep_action(std::string(v));
}

void xm_env_export() {
    char* v = std::getenv("XM_EXPORT"); if (!v) return;
    xm_export_action("events", std::string(v));
}

void xm_env_import() {
    char* v = std::getenv("XM_IMPORT"); if (!v) return;
    xm_import_action(std::string(v));
}

void xm_env_report() {
    char* v = std::getenv("XM_REPORT"); if (!v) return;
    xm_save_report(std::string(v), "env report");
}

void xm_env_config() {
    char* v = std::getenv("XM_CONFIG"); if (!v) return;
    xm_save_config(std::string(v), "env value");
}

void xm_env_exec() {
    char* v = std::getenv("XM_EXEC"); if (!v) return;
    xm_exec_user_action(std::string(v));
}

// getline sources
void xm_line_select() {
    std::string cond; std::getline(std::cin, cond);
    xm_select_query("logs", cond);
}

void xm_line_admin() {
    std::string action; std::getline(std::cin, action);
    xm_admin_action(action);
}

void xm_line_export() {
    std::string path; std::getline(std::cin, path);
    xm_export_action("users", path);
}

// fgets sources
void xm_fgets_select() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    xm_select_query("data", std::string(buf));
}

void xm_fgets_admin() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    xm_admin_action(std::string(buf));
}

void xm_fgets_backup() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    xm_backup_action(std::string(buf));
}

// argv sources
void xm_argv_select(int argc, char* argv[]) {
    if (argc < 2) return;
    xm_select_query("args", std::string(argv[1]));
}

void xm_argv_admin(int argc, char* argv[]) {
    if (argc < 2) return;
    xm_admin_action(std::string(argv[1]));
}

void xm_argv_export(int argc, char* argv[]) {
    if (argc < 2) return;
    xm_export_action("data", std::string(argv[1]));
}

void xm_argv_exec(int argc, char* argv[]) {
    if (argc < 2) return;
    xm_exec_user_action(std::string(argv[1]));
}

int main(int argc, char* argv[]) {
    xm_select_entry(); xm_delete_entry(); xm_update_entry();
    xm_order_entry(); xm_read_query_entry(); xm_admin_entry_cmd();
    xm_backup_entry_cmd(); xm_download_entry_cmd(); xm_script_entry_cmd();
    xm_grep_entry_cmd(); xm_export_entry_cmd(); xm_import_entry_cmd();
    xm_report_entry(); xm_config_entry(); xm_upload_entry();
    xm_checkname_entry(); xm_formatlog_entry(); xm_exec_entry_cmd();
    xm_env_select(); xm_env_delete(); xm_env_admin();
    xm_env_backup(); xm_env_download(); xm_env_script();
    xm_env_grep(); xm_env_export(); xm_env_import();
    xm_env_report(); xm_env_config(); xm_env_exec();
    xm_line_select(); xm_line_admin(); xm_line_export();
    xm_fgets_select(); xm_fgets_admin(); xm_fgets_backup();
    xm_argv_select(argc, argv); xm_argv_admin(argc, argv);
    xm_argv_export(argc, argv); xm_argv_exec(argc, argv);
    return 0;
}
