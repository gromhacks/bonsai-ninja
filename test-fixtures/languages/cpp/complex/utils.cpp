#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <functional>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <iostream>

namespace utils {

// -- String sanitizers (safe) --

std::string escape_html(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&#x27;"; break;
            default: result += c;
        }
    }
    return result;
}

std::string escape_sql(const std::string& input) {
    std::string result;
    for (char c : input) {
        if (c == '\'') result += "''";
        else if (c == '\\') result += "\\\\";
        else result += c;
    }
    return result;
}

bool is_valid_identifier(const std::string& id) {
    if (id.empty()) return false;
    return std::all_of(id.begin(), id.end(), [](char c) {
        return std::isalnum(c) || c == '_' || c == '-';
    });
}

std::string sanitize_filename(const std::string& filename) {
    std::string result;
    for (char c : filename) {
        if (std::isalnum(c) || c == '.' || c == '_' || c == '-') {
            result += c;
        }
    }
    return result;
}

// -- String transforms (pass-through, do NOT sanitize) --

std::string trim(const std::string& str) {
    auto start = str.begin();
    while (start != str.end() && std::isspace(*start)) ++start;
    auto end = str.end();
    do { --end; } while (std::distance(start, end) > 0 && std::isspace(*end));
    return std::string(start, end + 1);
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream stream(str);
    std::string token;
    while (std::getline(stream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string join(const std::vector<std::string>& parts, const std::string& separator) {
    std::string result;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i > 0) result += separator;
        result += parts[i];
    }
    return result;
}

std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string to_upper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

unsigned int hash_string(const std::string& str) {
    unsigned int hash = 5381;
    for (char c : str) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

std::string generate_id(int length) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    for (int i = 0; i < length; i++) {
        result += chars[rand() % (sizeof(chars) - 1)];
    }
    return result;
}

bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// =========================================================================
// Vulnerable utility operations - each is a sink reachable from callers
// =========================================================================

// VULN: Command injection via system()
void run_system_command(const std::string& cmd) {
    system(cmd.c_str());
}

// VULN: Command injection via popen()
std::string run_pipeline(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) {
        result += buf;
    }
    pclose(pipe);
    return result;
}

// VULN: Path traversal via fopen()
void write_to_file(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

// VULN: Path traversal via ofstream
void write_to_stream(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

// VULN: Path traversal via ifstream read
std::string read_from_file(const std::string& path) {
    std::ifstream file(path);
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// VULN: Buffer overflow via strcpy()
void unsafe_string_copy(char* dest, const char* src) {
    strcpy(dest, src);
}

// VULN: Buffer overflow via strcat()
void unsafe_string_concat(char* dest, const char* src) {
    strcat(dest, src);
}

// VULN: Buffer overflow via sprintf()
void unsafe_sprintf(char* dest, const char* input) {
    sprintf(dest, "cmd: %s", input);
}

// VULN: Buffer overflow via memcpy()
void unsafe_memcpy(char* dest, const char* src, size_t len) {
    memcpy(dest, src, len);
}

// VULN: Format string via printf()
void unsafe_printf(const char* fmt) {
    printf(fmt);
}

// VULN: Format string via fprintf()
void unsafe_fprintf(const char* fmt) {
    fprintf(stderr, fmt);
}

// VULN: Command injection via execl()
void exec_command(const std::string& cmd) {
    execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
}

// =========================================================================
// Wrapper functions that add hops between source and sink
// =========================================================================

// 2-hop: format then execute
void format_and_run(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    run_system_command(cmd);
}

// 2-hop: build path then write
void build_and_write(const std::string& dir, const std::string& name, const std::string& content) {
    std::string path = dir + "/" + name;
    write_to_file(path, content);
}

// 2-hop: build path then read
std::string build_and_read(const std::string& dir, const std::string& name) {
    std::string path = dir + "/" + name;
    return read_from_file(path);
}

// 2-hop: format then pipeline
std::string format_and_pipe(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    return run_pipeline(cmd);
}

// 2-hop: normalize then system
void normalize_and_run(const std::string& raw_cmd) {
    std::string cmd = trim(raw_cmd);
    run_system_command(cmd);
}

// =========================================================================
// Standalone vulnerable functions with their own sources
// These create direct source->sink flows within utils.cpp
// =========================================================================

// VULN: cin -> system() via format_and_run
void util_run_cmd() {
    std::string input;
    std::cin >> input;
    format_and_run("/usr/bin/tool", input);
}

// VULN: cin -> popen() via format_and_pipe
void util_query_cmd() {
    std::string query;
    std::cin >> query;
    std::string result = format_and_pipe("grep", query);
}

// VULN: cin -> fopen() via build_and_write
void util_upload_cmd() {
    std::string filename;
    std::cin >> filename;
    build_and_write("/var/uploads", filename, "uploaded data");
}

// VULN: cin -> strcpy()
void util_name_cmd() {
    std::string name;
    std::cin >> name;
    char buf[32];
    unsafe_string_copy(buf, name.c_str());
}

// VULN: cin -> sprintf()
void util_format_cmd() {
    std::string fmt_input;
    std::cin >> fmt_input;
    char buf[256];
    unsafe_sprintf(buf, fmt_input.c_str());
}

// VULN: getenv -> system()
void util_env_tool_cmd() {
    char* cmd = std::getenv("TOOL_CMD");
    if (!cmd) return;
    std::string command(cmd);
    format_and_run("admin-tool", command);
}

// VULN: getenv -> popen()
void util_env_pipe_cmd() {
    char* pipe_cmd = std::getenv("PIPE_CMD");
    if (!pipe_cmd) return;
    std::string cmd(pipe_cmd);
    std::string result = format_and_pipe("process", cmd);
}

// VULN: getenv -> fopen() path traversal
void util_env_file_cmd() {
    char* file_path = std::getenv("FILE_PATH");
    if (!file_path) return;
    std::string path(file_path);
    write_to_file(path, "environment data");
}

// VULN: getenv -> execl()
void util_env_exec_cmd() {
    char* exec_cmd = std::getenv("EXEC_CMD");
    if (!exec_cmd) return;
    std::string cmd(exec_cmd);
    exec_command(cmd);
}

// VULN: getline -> system()
void util_line_run_cmd() {
    std::string line;
    std::getline(std::cin, line);
    normalize_and_run(line);
}

// VULN: getline -> fopen()
void util_line_file_cmd() {
    std::string path;
    std::getline(std::cin, path);
    std::string full_path = "/var/data/" + path;
    write_to_file(full_path, "data");
}

// VULN: getline -> popen()
void util_line_pipe_cmd() {
    std::string input;
    std::getline(std::cin, input);
    std::string result = run_pipeline("process " + input);
}

// VULN: fgets -> system()
void util_fgets_run_cmd() {
    char buf[512];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    std::string cmd(buf);
    run_system_command("exec " + cmd);
}

// VULN: fgets -> strcpy()
void util_fgets_buf_cmd() {
    char input[512];
    if (fgets(input, sizeof(input), stdin) == nullptr) return;
    char dest[32];
    unsafe_string_copy(dest, input);
}

// VULN: fgets -> sprintf()
void util_fgets_fmt_cmd() {
    char input[512];
    if (fgets(input, sizeof(input), stdin) == nullptr) return;
    char dest[1024];
    unsafe_sprintf(dest, input);
}

// VULN: getenv -> strcpy()
void util_env_buf_cmd() {
    char* env = std::getenv("BUFFER_DATA");
    if (!env) return;
    char dest[64];
    unsafe_string_copy(dest, env);
}

// VULN: getenv -> strcat()
void util_env_concat_cmd() {
    char* env = std::getenv("CONCAT_DATA");
    if (!env) return;
    char buf[64];
    strcpy(buf, "prefix_");
    unsafe_string_concat(buf, env);
}

// VULN: getenv -> memcpy()
void util_env_memcpy_cmd() {
    char* env = std::getenv("MEM_DATA");
    if (!env) return;
    char dest[32];
    unsafe_memcpy(dest, env, strlen(env));
}

// VULN: getenv -> printf() format string
void util_env_printf_cmd() {
    char* env = std::getenv("FMT_DATA");
    if (!env) return;
    unsafe_printf(env);
}

// VULN: getenv -> fprintf() format string
void util_env_fprintf_cmd() {
    char* env = std::getenv("FMT_ERR");
    if (!env) return;
    unsafe_fprintf(env);
}

// VULN: cin -> ofstream path traversal
void util_stream_write_cmd() {
    std::string path;
    std::cin >> path;
    write_to_stream("/var/logs/" + path, "log entry");
}

// VULN: cin -> ifstream path traversal
void util_stream_read_cmd() {
    std::string path;
    std::cin >> path;
    std::string content = read_from_file("/etc/" + path);
}

// VULN: getenv -> ofstream
void util_env_log_cmd() {
    char* log_path = std::getenv("LOG_PATH");
    if (!log_path) return;
    std::string path(log_path);
    write_to_stream(path, "application log");
}

// VULN: cin -> normalize -> system (3-hop)
void util_normalize_cmd() {
    std::string raw;
    std::getline(std::cin, raw);
    std::string trimmed = trim(raw);
    std::string lowered = to_lower(trimmed);
    run_system_command(lowered);
}

// VULN: getenv -> normalize -> popen (3-hop)
void util_env_norm_cmd() {
    char* env = std::getenv("NORM_CMD");
    if (!env) return;
    std::string raw(env);
    std::string trimmed = trim(raw);
    std::string result = run_pipeline(trimmed);
}

// VULN: cin -> build_and_read -> path traversal
void util_file_read_cmd() {
    std::string name;
    std::cin >> name;
    std::string content = build_and_read("/etc/config", name);
}

} // namespace utils
