#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <functional>
#include <cstring>

// =========================================================================
// Layer 3: Terminal sinks
// =========================================================================

void mod_exec_system(const std::string& cmd) {
    system(cmd.c_str());
}

std::string mod_exec_pipe(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    return result;
}

void mod_write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
}

void mod_write_fopen(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (f) { fprintf(f, "%s", content.c_str()); fclose(f); }
}

void mod_load_lib(const std::string& path) {
    dlopen(path.c_str(), 1);
}

// =========================================================================
// Layer 2: Command builders
// =========================================================================

void mod_run_tool(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    mod_exec_system(cmd);
}

void mod_run_pipe(const std::string& tool, const std::string& args) {
    std::string cmd = tool + " " + args;
    mod_exec_pipe(cmd);
}

void mod_save_to(const std::string& dir, const std::string& name, const std::string& data) {
    std::string path = dir + "/" + name;
    mod_write_file(path, data);
}

void mod_save_fopen(const std::string& dir, const std::string& name, const std::string& data) {
    std::string path = dir + "/" + name;
    mod_write_fopen(path, data);
}

void mod_load_from(const std::string& dir, const std::string& name) {
    std::string path = dir + "/" + name;
    mod_load_lib(path);
}

// =========================================================================
// Layer 1: Mod operations
// =========================================================================

void install_mod(const std::string& url) {
    mod_run_tool("curl", "-sL " + url + " | tar xz -C /opt/game/mods/");
    mod_save_to("/var/log/mods", "install.log", url);
}

void compile_mod(const std::string& source) {
    mod_run_tool("g++", "-shared -o mod.so " + source);
    mod_run_pipe("nm", "-D mod.so");
}

void verify_mod(const std::string& sig) {
    mod_run_tool("gpg", "--verify " + sig);
    mod_save_to("/var/log/mods", "verify.log", sig);
}

void download_mod(const std::string& mod_id) {
    mod_run_tool("wget", "-O /tmp/" + mod_id + ".zip https://mods.example.com/" + mod_id);
    mod_run_pipe("sha256sum", "/tmp/" + mod_id + ".zip");
}

void extract_mod(const std::string& archive) {
    mod_run_tool("unzip", archive + " -d /opt/game/mods/");
    mod_save_to("/var/log/mods", "extract.log", archive);
}

void check_mod_status(const std::string& name) {
    mod_run_pipe("mod-checker", name);
    mod_save_to("/var/log/mods", "status.log", name);
}

void update_plugin(const std::string& name, const std::string& version) {
    mod_run_tool("plugin-manager", "update " + name + " --version " + version);
    mod_save_to("/var/log/plugins", "update.log", name);
}

void convert_asset(const std::string& input) {
    mod_run_tool("asset-converter", input);
    mod_run_pipe("file", input);
}

void optimize_asset(const std::string& path) {
    mod_run_pipe("asset-optimizer", path);
    mod_save_to("/var/log/assets", "optimize.log", path);
}

void import_textures(const std::string& url) {
    mod_run_tool("wget", "-O /tmp/textures.zip " + url);
    mod_save_to("/var/log/textures", "import.log", url);
}

void evaluate_script(const std::string& script) {
    mod_run_tool("lua", "-e \"" + script + "\"");
    mod_save_to("/var/log/scripts", "eval.log", script);
}

void check_script_syntax(const std::string& name) {
    mod_run_pipe("lua", "-p /opt/game/scripts/" + name);
    mod_save_to("/var/log/syntax", "check.log", name);
}

void run_script_file(const std::string& name) {
    mod_run_tool("lua", "/opt/game/scripts/" + name);
    mod_run_pipe("lua", "-p /opt/game/scripts/" + name);
}

void save_mod_config(const std::string& mod_name, const std::string& data) {
    mod_save_to("/opt/game/mods", mod_name + "/config.json", data);
}

void save_script(const std::string& name, const std::string& code) {
    mod_save_to("/opt/game/scripts", name, code);
}

void save_asset(const std::string& name, const std::string& data) {
    mod_save_fopen("/opt/game/assets", name, data);
}

void load_mod_lib(const std::string& name) {
    mod_load_from("/opt/game/mods", name + ".so");
}

void load_mod_config_path(const std::string& mod_name) {
    std::string path = "/opt/game/mods/" + mod_name + "/config.json";
    std::ifstream file(path);
}

void load_asset_file(const std::string& name) {
    std::string path = "/opt/game/assets/" + name;
    std::ifstream file(path, std::ios::binary);
}

// =========================================================================
// Layer 0: Source -> 4-hop chains
// =========================================================================

// cin -> install_mod -> mod_run_tool -> mod_exec_system -> system
void mod_install_cmd() {
    std::string url; std::cin >> url;
    install_mod(url);
}

void mod_compile_cmd() {
    std::string src; std::cin >> src;
    compile_mod(src);
}

void mod_verify_cmd() {
    std::string sig; std::cin >> sig;
    verify_mod(sig);
}

void mod_download_cmd() {
    std::string id; std::cin >> id;
    download_mod(id);
}

void mod_extract_cmd() {
    std::string arc; std::cin >> arc;
    extract_mod(arc);
}

void mod_status_cmd() {
    std::string name; std::cin >> name;
    check_mod_status(name);
}

void mod_update_cmd() {
    std::string name; std::cin >> name;
    update_plugin(name, "latest");
}

void mod_convert_cmd() {
    std::string input; std::cin >> input;
    convert_asset(input);
}

void mod_optimize_cmd() {
    std::string path; std::cin >> path;
    optimize_asset(path);
}

void mod_import_tex_cmd() {
    std::string url; std::cin >> url;
    import_textures(url);
}

void mod_eval_script_cmd() {
    std::string script; std::getline(std::cin, script);
    evaluate_script(script);
}

void mod_check_syntax() {
    std::string name; std::cin >> name;
    check_script_syntax(name);
}

void mod_run_script() {
    std::string name; std::cin >> name;
    run_script_file(name);
}

void mod_save_config() {
    std::string name; std::cin >> name;
    save_mod_config(name, "{}");
}

void mod_save_script() {
    std::string name; std::cin >> name;
    save_script(name, "-- script");
}

void mod_save_asset() {
    std::string name; std::cin >> name;
    save_asset(name, "asset data");
}

void mod_load_lib() {
    std::string name; std::cin >> name;
    load_mod_lib(name);
}

void mod_load_config() {
    std::string name; std::cin >> name;
    load_mod_config_path(name);
}

void mod_load_asset() {
    std::string name; std::cin >> name;
    load_asset_file(name);
}

// getenv sources
void mod_env_install() {
    char* v = std::getenv("MOD_URL"); if (!v) return;
    install_mod(std::string(v));
}

void mod_env_compile() {
    char* v = std::getenv("MOD_SOURCE"); if (!v) return;
    compile_mod(std::string(v));
}

void mod_env_download() {
    char* v = std::getenv("MOD_ID"); if (!v) return;
    download_mod(std::string(v));
}

void mod_env_extract() {
    char* v = std::getenv("MOD_ARCHIVE"); if (!v) return;
    extract_mod(std::string(v));
}

void mod_env_update() {
    char* v = std::getenv("PLUGIN_NAME"); if (!v) return;
    update_plugin(std::string(v), "latest");
}

void mod_env_textures() {
    char* v = std::getenv("TEXTURE_URL"); if (!v) return;
    import_textures(std::string(v));
}

void mod_env_run_script() {
    char* v = std::getenv("SCRIPT_NAME"); if (!v) return;
    run_script_file(std::string(v));
}

void mod_env_load_lib() {
    char* v = std::getenv("LIB_NAME"); if (!v) return;
    load_mod_lib(std::string(v));
}

void mod_env_config() {
    char* v = std::getenv("MOD_NAME"); if (!v) return;
    load_mod_config_path(std::string(v));
}

void mod_env_asset() {
    char* v = std::getenv("ASSET_NAME"); if (!v) return;
    load_asset_file(std::string(v));
}

void mod_env_eval() {
    char* v = std::getenv("EVAL_SCRIPT"); if (!v) return;
    evaluate_script(std::string(v));
}

void mod_env_convert() {
    char* v = std::getenv("CONVERT_INPUT"); if (!v) return;
    convert_asset(std::string(v));
}

// fgets sources
void mod_fgets_install() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    install_mod(std::string(buf));
}

void mod_fgets_compile() {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == nullptr) return;
    compile_mod(std::string(buf));
}

// getline sources
void mod_line_eval() {
    std::string script; std::getline(std::cin, script);
    evaluate_script(script);
}

void mod_line_install() {
    std::string url; std::getline(std::cin, url);
    install_mod(url);
}
