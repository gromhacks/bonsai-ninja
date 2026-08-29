#include <iostream>
#include <string>
#include <memory>
#include <optional>
#include <variant>
#include <vector>
#include <algorithm>
#include <numeric>
#include <functional>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <stdexcept>
#include <map>
#include <cstring>

// =========================================================================
// Advanced C++ patterns with multi-hop chains
// =========================================================================

// --- Smart pointer chain: cin -> unique_ptr -> shared_ptr -> system ---

void vuln_smart_pointer_taint() {
    std::string user_input;
    std::cin >> user_input;
    auto owned = std::make_unique<std::string>("run " + user_input);
    std::shared_ptr<std::string> shared = std::move(owned);
    std::string cmd = *shared;
    system(cmd.c_str());
}

// --- Template chain: getenv -> process<T> -> system ---

template <typename T>
T process_value(const T& value) { return value; }

void vuln_template_taint() {
    char* env = std::getenv("CMD");
    if (!env) return;
    std::string processed = process_value<std::string>(std::string(env));
    std::string cmd = "handler " + processed;
    system(cmd.c_str());
}

// --- Lambda capture chain: argv -> build_cmd -> lambda -> popen ---

void vuln_lambda_capture(int argc, char* argv[]) {
    if (argc < 2) return;
    std::string user_cmd(argv[1]);
    std::string full_cmd = "sh -c " + user_cmd;
    auto executor = [&full_cmd]() {
        FILE* pipe = popen(full_cmd.c_str(), "r");
        if (pipe) pclose(pipe);
    };
    executor();
}

// --- Optional chain: cin -> optional -> value_or -> system ---

void vuln_optional_taint() {
    std::string input;
    std::getline(std::cin, input);
    std::optional<std::string> filter = input.empty() ? std::nullopt : std::optional<std::string>(input);
    std::string clause = filter.value_or("1=1");
    std::string cmd = "sqlite3 db.sqlite \"SELECT * FROM users WHERE " + clause + "\"";
    system(cmd.c_str());
}

// --- Virtual dispatch chain: cin -> ShellExecutor::execute -> system ---

class Executor {
public:
    virtual void execute(const std::string& input) = 0;
    virtual ~Executor() = default;
};

class ShellExecutor : public Executor {
public:
    void execute(const std::string& input) override {
        std::string cmd = "process " + input;
        system(cmd.c_str());
    }
};

void vuln_virtual_dispatch() {
    std::string user_input;
    std::cin >> user_input;
    auto exec = std::make_unique<ShellExecutor>();
    exec->execute(user_input);
}

// --- Move semantics chain: cin -> build -> move -> system ---

void vuln_move_semantics() {
    std::string user_data;
    std::cin >> user_data;
    std::string command = "exec " + std::move(user_data);
    system(command.c_str());
}

// --- Structured bindings: cin -> pair -> fopen ---

void vuln_structured_bindings() {
    std::string filename, content;
    std::cin >> filename >> content;
    std::string path = "/var/uploads/" + filename;
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

// --- Exception taint: getenv -> throw -> catch -> system ---

void vuln_exception_taint() {
    char* user_data = std::getenv("USER_DATA");
    if (!user_data) return;
    std::string input(user_data);
    try {
        if (input.find(";") != std::string::npos) {
            throw std::runtime_error("Bad: " + input);
        }
    } catch (const std::runtime_error& e) {
        std::string cmd = std::string("cleanup ") + e.what();
        system(cmd.c_str());
    }
}

// --- Aggregate init: argv -> struct -> system ---

struct JobConfig {
    std::string command;
    int priority;
};

void vuln_aggregate_init(int argc, char* argv[]) {
    if (argc < 2) return;
    JobConfig job = {std::string(argv[1]), 5};
    std::string cmd = job.command + " --priority=" + std::to_string(job.priority);
    system(cmd.c_str());
}

// =========================================================================
// Additional standalone vulnerable functions with diverse sinks
// =========================================================================

// --- cin source -> various sinks ---

void adv_cin_system() {
    std::string cmd;
    std::cin >> cmd;
    system(("tool " + cmd).c_str());
}

void adv_cin_popen() {
    std::string cmd;
    std::cin >> cmd;
    FILE* pipe = popen(("check " + cmd).c_str(), "r");
    if (pipe) pclose(pipe);
}

void adv_cin_fopen() {
    std::string path;
    std::cin >> path;
    FILE* f = fopen(("/var/" + path).c_str(), "w");
    if (f) fclose(f);
}

void adv_cin_ofstream() {
    std::string path;
    std::cin >> path;
    std::ofstream file("/tmp/" + path);
    file << "data";
}

void adv_cin_strcpy() {
    std::string input;
    std::cin >> input;
    char buf[16];
    strcpy(buf, input.c_str());
}

void adv_cin_strcat() {
    std::string input;
    std::cin >> input;
    char buf[64];
    strcpy(buf, "prefix_");
    strcat(buf, input.c_str());
}

void adv_cin_sprintf() {
    std::string data;
    std::cin >> data;
    char buf[128];
    sprintf(buf, "value: %s", data.c_str());
}

void adv_cin_memcpy() {
    std::string input;
    std::cin >> input;
    char buf[32];
    memcpy(buf, input.c_str(), input.size());
}

void adv_cin_execl() {
    std::string cmd;
    std::cin >> cmd;
    execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
}

void adv_cin_printf() {
    std::string fmt;
    std::cin >> fmt;
    printf(fmt.c_str());
}

void adv_cin_fprintf() {
    std::string fmt;
    std::cin >> fmt;
    fprintf(stderr, fmt.c_str());
}

void adv_cin_ifstream() {
    std::string path;
    std::cin >> path;
    std::ifstream file("/etc/" + path);
}

// --- getenv source -> various sinks ---

void adv_env_system() {
    char* cmd = std::getenv("ADV_CMD");
    if (!cmd) return;
    system(cmd);
}

void adv_env_popen() {
    char* cmd = std::getenv("ADV_PIPE");
    if (!cmd) return;
    FILE* pipe = popen(cmd, "r");
    if (pipe) pclose(pipe);
}

void adv_env_fopen() {
    char* path = std::getenv("ADV_FILE");
    if (!path) return;
    FILE* f = fopen(path, "w");
    if (f) fclose(f);
}

void adv_env_ofstream() {
    char* path = std::getenv("ADV_PATH");
    if (!path) return;
    std::ofstream file(path);
    file << "env data";
}

void adv_env_strcpy() {
    char* data = std::getenv("ADV_BUF");
    if (!data) return;
    char buf[32];
    strcpy(buf, data);
}

void adv_env_sprintf() {
    char* data = std::getenv("ADV_FMT");
    if (!data) return;
    char buf[256];
    sprintf(buf, "env: %s", data);
}

void adv_env_memcpy() {
    char* data = std::getenv("ADV_MEM");
    if (!data) return;
    char buf[32];
    memcpy(buf, data, strlen(data));
}

void adv_env_execl() {
    char* cmd = std::getenv("ADV_EXEC");
    if (!cmd) return;
    execl("/bin/sh", "sh", "-c", cmd, nullptr);
}

void adv_env_printf() {
    char* fmt = std::getenv("ADV_PRINTF");
    if (!fmt) return;
    printf(fmt);
}

// --- getline source -> various sinks ---

void adv_line_system() {
    std::string line;
    std::getline(std::cin, line);
    system(("process " + line).c_str());
}

void adv_line_popen() {
    std::string line;
    std::getline(std::cin, line);
    FILE* pipe = popen(("analyze " + line).c_str(), "r");
    if (pipe) pclose(pipe);
}

void adv_line_fopen() {
    std::string path;
    std::getline(std::cin, path);
    FILE* f = fopen(path.c_str(), "w");
    if (f) fclose(f);
}

void adv_line_ofstream() {
    std::string path;
    std::getline(std::cin, path);
    std::ofstream file(path);
    file << "line data";
}

void adv_line_strcpy() {
    std::string line;
    std::getline(std::cin, line);
    char buf[16];
    strcpy(buf, line.c_str());
}

// --- fgets source -> various sinks ---

void adv_fgets_system() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    std::string cmd = "run " + std::string(buf);
    system(cmd.c_str());
}

void adv_fgets_popen() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    FILE* pipe = popen(buf, "r");
    if (pipe) pclose(pipe);
}

void adv_fgets_strcpy() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    char dest[16];
    strcpy(dest, buf);
}

void adv_fgets_sprintf() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    char dest[512];
    sprintf(dest, "input: %s", buf);
}

// --- argv source -> various sinks ---

void adv_argv_system(int argc, char* argv[]) {
    if (argc < 2) return;
    std::string cmd = "tool " + std::string(argv[1]);
    system(cmd.c_str());
}

void adv_argv_popen(int argc, char* argv[]) {
    if (argc < 2) return;
    std::string cmd = "check " + std::string(argv[1]);
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) pclose(pipe);
}

void adv_argv_fopen(int argc, char* argv[]) {
    if (argc < 2) return;
    FILE* f = fopen(argv[1], "w");
    if (f) fclose(f);
}

void adv_argv_strcpy(int argc, char* argv[]) {
    if (argc < 2) return;
    char buf[16];
    strcpy(buf, argv[1]);
}

void adv_argv_sprintf(int argc, char* argv[]) {
    if (argc < 2) return;
    char buf[256];
    sprintf(buf, "arg: %s", argv[1]);
}

void adv_argv_memcpy(int argc, char* argv[]) {
    if (argc < 2) return;
    char buf[32];
    memcpy(buf, argv[1], strlen(argv[1]));
}

void adv_argv_execl(int argc, char* argv[]) {
    if (argc < 2) return;
    execl("/bin/sh", "sh", "-c", argv[1], nullptr);
}

void adv_argv_ofstream(int argc, char* argv[]) {
    if (argc < 2) return;
    std::ofstream file(argv[1]);
    file << "argv data";
}

// =========================================================================
// Entry point
// =========================================================================

int main(int argc, char* argv[]) {
    vuln_smart_pointer_taint();
    vuln_template_taint();
    vuln_lambda_capture(argc, argv);
    vuln_optional_taint();
    vuln_virtual_dispatch();
    vuln_move_semantics();
    vuln_structured_bindings();
    vuln_exception_taint();
    vuln_aggregate_init(argc, argv);

    adv_cin_system();
    adv_cin_popen();
    adv_cin_fopen();
    adv_cin_ofstream();
    adv_cin_strcpy();
    adv_cin_strcat();
    adv_cin_sprintf();
    adv_cin_memcpy();
    adv_cin_execl();
    adv_cin_printf();
    adv_cin_fprintf();
    adv_cin_ifstream();

    adv_env_system();
    adv_env_popen();
    adv_env_fopen();
    adv_env_ofstream();
    adv_env_strcpy();
    adv_env_sprintf();
    adv_env_memcpy();
    adv_env_execl();
    adv_env_printf();

    adv_line_system();
    adv_line_popen();
    adv_line_fopen();
    adv_line_ofstream();
    adv_line_strcpy();

    adv_fgets_system();
    adv_fgets_popen();
    adv_fgets_strcpy();
    adv_fgets_sprintf();

    adv_argv_system(argc, argv);
    adv_argv_popen(argc, argv);
    adv_argv_fopen(argc, argv);
    adv_argv_strcpy(argc, argv);
    adv_argv_sprintf(argc, argv);
    adv_argv_memcpy(argc, argv);
    adv_argv_execl(argc, argv);
    adv_argv_ofstream(argc, argv);

    return 0;
}

// ============================================================
// ADDITIONAL PATTERNS - RAII, std::function, structured bindings
// ============================================================

// RAII with taint in destructor
class CommandScope {
    std::string cmd_;
public:
    CommandScope(const std::string& cmd) : cmd_(cmd) {}
    ~CommandScope() {
        system(cmd_.c_str());  // taint released in destructor
    }
};

void raii_flow(const std::string& input) {
    CommandScope scope(input);  // taint stored via RAII
}  // destructor executes command

// std::function wrapper
void function_wrapper_flow(const std::string& input) {
    std::function<void()> fn = [&input]() {
        system(input.c_str());  // taint captured by std::function
    };
    fn();
}

// Structured bindings with taint
void structured_binding_flow(const std::string& input) {
    auto [cmd, arg] = std::make_pair(input, std::string("flag"));
    system(cmd.c_str());  // taint through structured binding
}

// std::variant dispatch
void variant_flow(const std::string& input) {
    std::variant<std::string, int> v = input;
    if (auto* cmd = std::get_if<std::string>(&v)) {
        system(cmd->c_str());  // taint through variant
    }
}

// Range-based for with taint
void range_flow(const std::vector<std::string>& inputs) {
    for (const auto& cmd : inputs) {
        system(cmd.c_str());  // taint through range
    }
}

// Lambda with capture
void lambda_capture_flow(const std::string& input) {
    auto fn = [&]() { system(input.c_str()); };
    fn();
}
