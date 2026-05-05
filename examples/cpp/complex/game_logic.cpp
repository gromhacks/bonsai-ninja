#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <memory>
#include <sstream>
#include <fstream>
#include <cstdio>

// =========================================================================
// Layer 3: Terminal sinks
// =========================================================================

void game_exec_system(const std::string& cmd) {
    system(cmd.c_str());
}

std::string game_exec_pipe(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    return result;
}

void game_write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

void game_write_fopen(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

void game_copy_buf(char* dest, const char* src) {
    strcpy(dest, src);
}

void game_format_buf(char* dest, const char* src) {
    sprintf(dest, "game: %s", src);
}

void game_exec_binary(const std::string& cmd) {
    execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
}

// =========================================================================
// Layer 2: Command/path builders
// =========================================================================

void game_run_tool(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    game_exec_system(cmd);
}

void game_run_pipe_tool(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    game_exec_pipe(cmd);
}

void game_save_data(const std::string& dir, const std::string& name, const std::string& data) {
    std::string path = dir + "/" + name;
    game_write_file(path, data);
}

void game_save_fopen(const std::string& dir, const std::string& name, const std::string& data) {
    std::string path = dir + "/" + name;
    game_write_fopen(path, data);
}

void game_process_buffer(const std::string& input) {
    char buf[32];
    game_copy_buf(buf, input.c_str());
}

void game_format_data(const std::string& input) {
    char buf[256];
    game_format_buf(buf, input.c_str());
}

// =========================================================================
// Layer 1: Game operations
// =========================================================================

void run_player_script(const std::string& script) {
    game_run_tool("/opt/game/scripts/run.sh", script);
    game_save_data("/var/game/logs", "script.log", script);
}

void export_profile(const std::string& pid, const std::string& fmt) {
    game_run_tool("game-export", "--player " + pid + " --format " + fmt);
    game_save_data("/var/game/exports", pid + ".dat", fmt);
}

void backup_world(const std::string& world) {
    game_run_tool("tar", "czf /var/backups/" + world + ".tar.gz /var/game/worlds/" + world);
    game_run_pipe_tool("sha256sum", "/var/backups/" + world + ".tar.gz");
}

void process_replay(const std::string& replay) {
    game_run_pipe_tool("replay-parser", replay);
    game_save_data("/var/game/replays", "parsed.log", replay);
}

void log_match(const std::string& details) {
    game_run_tool("echo", details + " >> /var/log/matches.log");
    game_save_data("/var/game/matches", "latest.log", details);
}

void generate_map(const std::string& params) {
    game_run_tool("map-generator", params);
    game_run_pipe_tool("map-validator", params);
}

void unlock_achievement(const std::string& id) {
    game_run_tool("achievement-service", "unlock " + id);
    game_save_data("/var/game/achievements", id + ".json", id);
}

void check_anticheat(const std::string& hash) {
    game_run_pipe_tool("anticheat-verify", hash);
    game_run_tool("anticheat-log", hash);
}

void execute_chat_action(const std::string& cmd) {
    game_run_tool("chat-bot", cmd);
    game_save_data("/var/game/chatlogs", "commands.log", cmd);
}

void save_player(const std::string& filename, const std::string& data) {
    game_save_data("/var/game/saves", filename, data);
    game_run_tool("notify-service", "saved " + filename);
}

void save_replay(const std::string& filename, const std::string& data) {
    game_save_fopen("/var/game/replays", filename, data);
    game_run_tool("index-replay", filename);
}

void save_chat_log(const std::string& channel, const std::string& msg) {
    game_save_data("/var/game/chatlogs", channel + ".log", msg);
    game_run_tool("chat-index", channel);
}

void load_world_config(const std::string& config) {
    std::string path = "/var/game/worlds/" + config;
    std::ifstream file(path);
}

void load_texture(const std::string& texture) {
    std::string path = "/var/game/textures/" + texture;
    std::ifstream file(path, std::ios::binary);
}

void process_name(const std::string& name) {
    game_process_buffer(name);
}

void format_stats(const std::string& name) {
    game_format_data(name);
}

void execute_player_action(const std::string& cmd) {
    game_exec_binary(cmd);
}

void format_chat(const std::string& username, const std::string& msg) {
    char buf[512];
    sprintf(buf, "[%s] %s", username.c_str(), msg.c_str());
}

void run_sql_via_game(const std::string& table, const std::string& condition) {
    std::string cmd = "sqlite3 game.db \"SELECT * FROM " + table + " WHERE " + condition + "\"";
    game_exec_system(cmd);
}

// =========================================================================
// Layer 0: Source -> 4-hop chain entries
// =========================================================================

// cin -> run_player_script -> game_run_tool -> game_exec_system -> system
void game_script_cmd() {
    std::string script; std::cin >> script;
    run_player_script(script);
}

void game_export_cmd() {
    std::string fmt; std::cin >> fmt;
    export_profile("player1", fmt);
}

void game_backup_cmd() {
    std::string world; std::cin >> world;
    backup_world(world);
}

void game_replay_cmd() {
    std::string replay; std::cin >> replay;
    process_replay(replay);
}

void game_matchlog_cmd() {
    std::string details; std::getline(std::cin, details);
    log_match(details);
}

void game_map_cmd() {
    std::string params; std::cin >> params;
    generate_map(params);
}

void game_achievement_cmd() {
    std::string id; std::cin >> id;
    unlock_achievement(id);
}

void game_anticheat_cmd() {
    std::string hash; std::cin >> hash;
    check_anticheat(hash);
}

void game_chat_cmd() {
    std::string cmd; std::cin >> cmd;
    execute_chat_action(cmd);
}

void game_save_cmd() {
    std::string filename; std::cin >> filename;
    save_player(filename, "save data");
}

void game_savereplay_cmd() {
    std::string filename; std::cin >> filename;
    save_replay(filename, "replay data");
}

void game_chatlog_cmd() {
    std::string channel; std::cin >> channel;
    save_chat_log(channel, "chat message");
}

void game_name_cmd() {
    std::string name; std::cin >> name;
    process_name(name);
}

void game_statsfmt_cmd() {
    std::string name; std::cin >> name;
    format_stats(name);
}

void game_player_cmd() {
    std::string cmd; std::cin >> cmd;
    execute_player_action(cmd);
}

void game_sql_cmd() {
    std::string cond; std::cin >> cond;
    run_sql_via_game("players", cond);
}

// getenv sources
void game_env_script() {
    char* v = std::getenv("GAME_SCRIPT"); if (!v) return;
    run_player_script(std::string(v));
}

void game_env_backup() {
    char* v = std::getenv("GAME_WORLD"); if (!v) return;
    backup_world(std::string(v));
}

void game_env_map() {
    char* v = std::getenv("MAP_PARAMS"); if (!v) return;
    generate_map(std::string(v));
}

void game_env_anticheat() {
    char* v = std::getenv("PLAYER_HASH"); if (!v) return;
    check_anticheat(std::string(v));
}

void game_env_replay() {
    char* v = std::getenv("REPLAY_PATH"); if (!v) return;
    process_replay(std::string(v));
}

void game_env_achievement() {
    char* v = std::getenv("ACHIEVEMENT_ID"); if (!v) return;
    unlock_achievement(std::string(v));
}

void game_env_chat() {
    char* v = std::getenv("CHAT_CMD"); if (!v) return;
    execute_chat_action(std::string(v));
}

void game_env_save() {
    char* v = std::getenv("SAVE_FILE"); if (!v) return;
    save_player(std::string(v), "env save");
}

void game_env_config() {
    char* v = std::getenv("GAME_CONFIG"); if (!v) return;
    load_world_config(std::string(v));
}

void game_env_texture() {
    char* v = std::getenv("TEXTURE_PATH"); if (!v) return;
    load_texture(std::string(v));
}

void game_env_exec() {
    char* v = std::getenv("GAME_CMD"); if (!v) return;
    execute_player_action(std::string(v));
}

void game_env_sql() {
    char* v = std::getenv("GAME_QUERY"); if (!v) return;
    run_sql_via_game("data", std::string(v));
}

// fgets sources
void game_fgets_script() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    run_player_script(std::string(buf));
}

void game_fgets_entry() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    game_run_tool("game-admin", std::string(buf));
}

// getline sources
void game_line_script() {
    std::string s; std::getline(std::cin, s);
    run_player_script(s);
}

void game_line_export() {
    std::string fmt; std::getline(std::cin, fmt);
    export_profile("p1", fmt);
}
