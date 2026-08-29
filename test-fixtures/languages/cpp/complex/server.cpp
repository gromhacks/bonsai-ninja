#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fstream>
#include <sstream>

constexpr int MAX_BUFFER = 4096;
constexpr int SERVER_PORT = 7777;

struct PlayerSession {
    int socket_fd;
    std::string player_id;
    std::string username;
    bool authenticated;
};

// =========================================================================
// Layer 3 (deepest): Terminal sink wrappers
// =========================================================================

void execute_shell_op(const std::string& cmd) {
    system(cmd.c_str());
}

std::string execute_pipe_op(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    return result;
}

void write_file_content(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

void write_file_fopen(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

void copy_to_buffer(char* dest, const char* src) {
    strcpy(dest, src);
}

void format_to_buffer(char* dest, const char* src) {
    sprintf(dest, "data: %s", src);
}

void exec_shell(const std::string& cmd) {
    execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
}

// =========================================================================
// Layer 2 (middle): Command/query builders
// =========================================================================

void run_admin_command(const std::string& args) {
    std::string cmd = "server-admin " + args;
    execute_shell_op(cmd);
}

void run_service_check(const std::string& service) {
    std::string cmd = "systemctl status " + service;
    execute_pipe_op(cmd);
}

void run_sql_query(const std::string& sql) {
    std::string cmd = "sqlite3 db.sqlite \"" + sql + "\"";
    execute_shell_op(cmd);
}

void run_sql_read(const std::string& sql) {
    std::string cmd = "sqlite3 db.sqlite \"" + sql + "\"";
    execute_pipe_op(cmd);
}

void save_to_path(const std::string& dir, const std::string& name, const std::string& content) {
    std::string path = dir + "/" + name;
    write_file_content(path, content);
}

void save_to_fopen(const std::string& dir, const std::string& name, const std::string& content) {
    std::string path = dir + "/" + name;
    write_file_fopen(path, content);
}

void run_backup(const std::string& name) {
    std::string cmd = "tar czf /var/backups/" + name + ".tar.gz /var/game/";
    execute_shell_op(cmd);
}

void run_script(const std::string& script) {
    std::string cmd = "lua /opt/game/scripts/" + script;
    execute_pipe_op(cmd);
}

void run_download(const std::string& url) {
    std::string cmd = "curl -sL " + url + " | tar xz";
    execute_shell_op(cmd);
}

void run_grep(const std::string& pattern) {
    std::string cmd = "grep -r \"" + pattern + "\" /var/log/";
    execute_pipe_op(cmd);
}

void process_name_buffer(const std::string& name) {
    char buf[32];
    copy_to_buffer(buf, name.c_str());
}

void format_log_buffer(const std::string& msg) {
    char buf[256];
    format_to_buffer(buf, msg.c_str());
}

// =========================================================================
// Layer 1 (handlers): Parse input and delegate to Layer 2
// =========================================================================

void handle_admin(const std::string& payload) {
    run_admin_command(payload);
    save_to_path("/var/log/admin", "admin.log", payload);
}

void handle_search(const std::string& query) {
    std::string sql = "SELECT * FROM players WHERE name LIKE '%" + query + "%'";
    run_sql_query(sql);
    save_to_path("/var/log/searches", "search.log", query);
}

void handle_mod(const std::string& url) {
    run_download(url);
    save_to_path("/var/log/mods", "download.log", url);
}

void handle_backup(const std::string& name) {
    run_backup(name);
    run_service_check("backup-" + name);
}

void handle_query(const std::string& condition) {
    std::string sql = "SELECT * FROM data WHERE " + condition;
    run_sql_query(sql);
    save_to_path("/var/log/queries", "query.log", condition);
}

void handle_script(const std::string& script) {
    run_script(script);
    save_to_path("/var/log/scripts", "script.log", script);
}

void handle_export(const std::string& filename) {
    save_to_path("/var/game/exports", filename, "export data");
    run_admin_command("chmod 644 /var/game/exports/" + filename);
}

void handle_config(const std::string& data) {
    size_t eq = data.find('=');
    if (eq == std::string::npos) return;
    std::string key = data.substr(0, eq);
    std::string value = data.substr(eq + 1);
    save_to_path("/var/game/config", key + ".conf", value);
}

void handle_audit(const std::string& filter) {
    std::string sql = "SELECT * FROM audit WHERE details LIKE '%" + filter + "%'";
    run_sql_query(sql);
    run_grep(filter);
}

void handle_leaderboard(const std::string& sort_field) {
    std::string sql = "SELECT * FROM players ORDER BY " + sort_field + " DESC";
    run_sql_query(sql);
    run_service_check("leaderboard");
}

void handle_status(const std::string& service) {
    run_service_check(service);
    save_to_path("/var/log/status", "check.log", service);
}

void handle_log_search(const std::string& pattern) {
    run_grep(pattern);
    save_to_path("/var/log/searches", "logsearch.log", pattern);
}

void handle_upload(const std::string& filename) {
    save_to_fopen("/var/uploads", filename, "uploaded");
    run_admin_command("chmod 644 /var/uploads/" + filename);
}

void handle_player_name(const std::string& name) {
    process_name_buffer(name);
    save_to_path("/var/log/names", "names.log", name);
}

void handle_format_log(const std::string& msg) {
    format_log_buffer(msg);
    save_to_path("/var/log/fmt", "format.log", msg);
}

void handle_delete(const std::string& id) {
    std::string sql = "DELETE FROM records WHERE id = '" + id + "'";
    run_sql_query(sql);
    save_to_path("/var/log/deletes", "delete.log", id);
}

void handle_update(const std::string& data) {
    std::string sql = "UPDATE config SET value = '" + data + "'";
    run_sql_query(sql);
    save_to_path("/var/log/updates", "update.log", data);
}

void handle_import(const std::string& path) {
    std::string cmd = "sqlite3 db.sqlite < " + path;
    execute_shell_op(cmd);
}

void handle_maintenance(const std::string& op) {
    std::string cmd = "sqlite3 db.sqlite \"" + op + "\"";
    execute_shell_op(cmd);
}

void handle_sort(const std::string& field) {
    std::string sql = "SELECT * FROM players ORDER BY " + field;
    run_sql_read(sql);
}

void handle_exec(const std::string& cmd) {
    exec_shell(cmd);
}

// =========================================================================
// Layer 0 (entry): Parse protocol and delegate to handlers
// =========================================================================

void dispatch_command(const std::string& command, const std::string& payload) {
    if (command == "ADMIN") handle_admin(payload);
    else if (command == "SEARCH") handle_search(payload);
    else if (command == "MOD") handle_mod(payload);
    else if (command == "BACKUP") handle_backup(payload);
    else if (command == "QUERY") handle_query(payload);
    else if (command == "SCRIPT") handle_script(payload);
    else if (command == "EXPORT") handle_export(payload);
    else if (command == "CONFIG") handle_config(payload);
    else if (command == "AUDIT") handle_audit(payload);
    else if (command == "LEAD") handle_leaderboard(payload);
    else if (command == "STATUS") handle_status(payload);
    else if (command == "LOG") handle_log_search(payload);
    else if (command == "UPLOAD") handle_upload(payload);
    else if (command == "NAME") handle_player_name(payload);
    else if (command == "FMTLOG") handle_format_log(payload);
    else if (command == "DELETE") handle_delete(payload);
    else if (command == "UPDATE") handle_update(payload);
    else if (command == "IMPORT") handle_import(payload);
    else if (command == "MAINT") handle_maintenance(payload);
    else if (command == "SORT") handle_sort(payload);
    else if (command == "EXEC") handle_exec(payload);
}

void process_message(const std::string& msg) {
    size_t colon = msg.find(':');
    if (colon == std::string::npos) return;
    std::string command = msg.substr(0, colon);
    std::string payload = msg.substr(colon + 1);
    dispatch_command(command, payload);
}

// =========================================================================
// GameServer class with recv source
// =========================================================================

class GameServer {
private:
    int server_socket;

public:
    GameServer(int port) {
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        bind(server_socket, (struct sockaddr*)&addr, sizeof(addr));
        listen(server_socket, 100);
    }

    void accept_and_handle() {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) return;
        handle_client(client_sock);
    }

    void handle_client(int client_sock) {
        char buffer[MAX_BUFFER];
        int bytes = recv(client_sock, buffer, MAX_BUFFER - 1, 0);
        if (bytes <= 0) return;
        buffer[bytes] = '\0';
        process_message(std::string(buffer));
    }

    void log_connection(const char* ip) {
        printf(ip);
    }
};

// =========================================================================
// Standalone source -> handler chains (3 hops each)
// =========================================================================

// cin -> handle_admin -> run_admin_command -> execute_shell_op -> system
void srv_admin_cmd() {
    std::string cmd; std::cin >> cmd;
    handle_admin(cmd);
}

// cin -> handle_search -> run_sql_query -> execute_shell_op -> system
void srv_search_cmd() {
    std::string q; std::cin >> q;
    handle_search(q);
}

// cin -> handle_mod -> run_download -> execute_shell_op -> system
void srv_mod_cmd() {
    std::string url; std::cin >> url;
    handle_mod(url);
}

// cin -> handle_backup -> run_backup -> execute_shell_op -> system
void srv_backup_cmd() {
    std::string name; std::cin >> name;
    handle_backup(name);
}

// cin -> handle_query -> run_sql_query -> execute_shell_op -> system
void srv_query_cmd() {
    std::string cond; std::cin >> cond;
    handle_query(cond);
}

// cin -> handle_script -> run_script -> execute_pipe_op -> popen
void srv_script_cmd() {
    std::string s; std::cin >> s;
    handle_script(s);
}

// cin -> handle_export -> save_to_path -> write_file_content -> ofstream
void srv_export_cmd() {
    std::string f; std::cin >> f;
    handle_export(f);
}

// cin -> handle_audit -> run_sql_query -> execute_shell_op -> system
void srv_audit_cmd() {
    std::string f; std::cin >> f;
    handle_audit(f);
}

// cin -> handle_leaderboard -> run_sql_query -> execute_shell_op -> system
void srv_lead_cmd() {
    std::string f; std::cin >> f;
    handle_leaderboard(f);
}

// cin -> handle_status -> run_service_check -> execute_pipe_op -> popen
void srv_status_cmd() {
    std::string s; std::cin >> s;
    handle_status(s);
}

// cin -> handle_log_search -> run_grep -> execute_pipe_op -> popen
void srv_log_cmd() {
    std::string p; std::cin >> p;
    handle_log_search(p);
}

// cin -> handle_upload -> save_to_fopen -> write_file_fopen -> fopen
void srv_upload_cmd() {
    std::string f; std::cin >> f;
    handle_upload(f);
}

// cin -> handle_player_name -> process_name_buffer -> copy_to_buffer -> strcpy
void srv_name_cmd() {
    std::string n; std::cin >> n;
    handle_player_name(n);
}

// cin -> handle_format_log -> format_log_buffer -> format_to_buffer -> sprintf
void srv_fmtlog_cmd() {
    std::string m; std::cin >> m;
    handle_format_log(m);
}

// cin -> handle_delete -> run_sql_query -> execute_shell_op -> system
void srv_delete_cmd() {
    std::string id; std::cin >> id;
    handle_delete(id);
}

// cin -> handle_update -> run_sql_query -> execute_shell_op -> system
void srv_update_cmd() {
    std::string d; std::getline(std::cin, d);
    handle_update(d);
}

// cin -> handle_import -> execute_shell_op -> system
void srv_import_cmd() {
    std::string p; std::cin >> p;
    handle_import(p);
}

// cin -> handle_exec -> exec_shell -> execl
void srv_exec_cmd() {
    std::string c; std::cin >> c;
    handle_exec(c);
}

// getenv -> handle_admin -> run_admin_command -> execute_shell_op -> system
void srv_env_admin_cmd() {
    char* v = std::getenv("SRV_ADMIN"); if (!v) return;
    handle_admin(std::string(v));
}

// getenv -> handle_search -> run_sql_query -> execute_shell_op -> system
void srv_env_search_cmd() {
    char* v = std::getenv("SRV_SEARCH"); if (!v) return;
    handle_search(std::string(v));
}

// getenv -> handle_script -> run_script -> execute_pipe_op -> popen
void srv_env_script_cmd() {
    char* v = std::getenv("SRV_SCRIPT"); if (!v) return;
    handle_script(std::string(v));
}

// getenv -> handle_export -> save_to_path -> write_file_content -> ofstream
void srv_env_export_cmd() {
    char* v = std::getenv("SRV_EXPORT"); if (!v) return;
    handle_export(std::string(v));
}

// getenv -> handle_backup -> run_backup -> execute_shell_op -> system
void srv_env_backup_cmd() {
    char* v = std::getenv("SRV_BACKUP"); if (!v) return;
    handle_backup(std::string(v));
}

// getenv -> handle_mod -> run_download -> execute_shell_op -> system
void srv_env_mod_cmd() {
    char* v = std::getenv("SRV_MOD"); if (!v) return;
    handle_mod(std::string(v));
}

// getenv -> handle_exec -> exec_shell -> execl
void srv_env_exec_cmd() {
    char* v = std::getenv("SRV_EXEC"); if (!v) return;
    handle_exec(std::string(v));
}

// getenv -> handle_upload -> save_to_fopen -> write_file_fopen -> fopen
void srv_env_upload_cmd() {
    char* v = std::getenv("SRV_UPLOAD"); if (!v) return;
    handle_upload(std::string(v));
}

// getenv -> handle_log_search -> run_grep -> execute_pipe_op -> popen
void srv_env_log_cmd() {
    char* v = std::getenv("SRV_LOG"); if (!v) return;
    handle_log_search(std::string(v));
}

// getline -> handle_query -> run_sql_query -> execute_shell_op -> system
void srv_line_query_cmd() {
    std::string q; std::getline(std::cin, q);
    handle_query(q);
}

// getline -> handle_config -> save_to_path -> write_file_content -> ofstream
void srv_line_config_cmd() {
    std::string c; std::getline(std::cin, c);
    handle_config(c);
}

// fgets -> handle_maintenance -> execute_shell_op -> system
void srv_fgets_maint_cmd() {
    char buf[512];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    handle_maintenance(std::string(buf));
}

// fgets -> handle_admin -> run_admin_command -> execute_shell_op -> system
void srv_fgets_admin_cmd() {
    char buf[512];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    handle_admin(std::string(buf));
}

// argv -> handle_admin -> run_admin_command -> execute_shell_op -> system
void srv_argv_admin_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_admin(std::string(argv[1]));
}

// argv -> handle_query -> run_sql_query -> execute_shell_op -> system
void srv_argv_query_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_query(std::string(argv[1]));
}

// argv -> handle_export -> save_to_path -> write_file_content -> ofstream
void srv_argv_export_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_export(std::string(argv[1]));
}

// argv -> handle_script -> run_script -> execute_pipe_op -> popen
void srv_argv_script_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_script(std::string(argv[1]));
}

// argv -> handle_exec -> exec_shell -> execl
void srv_argv_exec_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_exec(std::string(argv[1]));
}

// argv -> handle_upload -> save_to_fopen -> write_file_fopen -> fopen
void srv_argv_upload_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_upload(std::string(argv[1]));
}

// argv -> handle_player_name -> process_name_buffer -> copy_to_buffer -> strcpy
void srv_argv_name_cmd(int argc, char* argv[]) {
    if (argc < 2) return;
    handle_player_name(std::string(argv[1]));
}

int main(int argc, char* argv[]) {
    srv_admin_cmd(); srv_search_cmd(); srv_mod_cmd(); srv_backup_cmd();
    srv_query_cmd(); srv_script_cmd(); srv_export_cmd(); srv_audit_cmd();
    srv_lead_cmd(); srv_status_cmd(); srv_log_cmd(); srv_upload_cmd();
    srv_name_cmd(); srv_fmtlog_cmd(); srv_delete_cmd(); srv_update_cmd();
    srv_import_cmd(); srv_exec_cmd();
    srv_env_admin_cmd(); srv_env_search_cmd(); srv_env_script_cmd(); srv_env_export_cmd();
    srv_env_backup_cmd(); srv_env_mod_cmd(); srv_env_exec_cmd(); srv_env_upload_cmd(); srv_env_log_cmd();
    srv_line_query_cmd(); srv_line_config_cmd();
    srv_fgets_maint_cmd(); srv_fgets_admin_cmd();
    srv_argv_admin_cmd(argc, argv); srv_argv_query_cmd(argc, argv);
    srv_argv_export_cmd(argc, argv); srv_argv_script_cmd(argc, argv);
    srv_argv_exec_cmd(argc, argv); srv_argv_upload_cmd(argc, argv); srv_argv_name_cmd(argc, argv);

    GameServer server(SERVER_PORT);
    server.accept_and_handle();
    return 0;
}
