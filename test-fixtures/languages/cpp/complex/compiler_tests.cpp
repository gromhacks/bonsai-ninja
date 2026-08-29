/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

// [NO FLOW EXPECTED] Both branches sanitize
void branch_kill_both_paths(const std::string &user_input) {
    std::string cmd;
    if (user_input.length() > 100) {
        cmd = "default_command";
    } else {
        cmd = "safe_fallback";
    }
    std::system(cmd.c_str()); // safe
}

// [FLOW EXPECTED] Only one branch kills taint
void branch_kill_one_path(const std::string &user_input) {
    std::string cmd = user_input;
    if (cmd.length() > 100) {
        cmd = "truncated";
    }
    std::system(cmd.c_str()); // tainted: else path preserves
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

std::string sanitize(const std::string &value) {
    std::string result;
    for (char c : value) {
        if (c != '\'' && c != ';') {
            result += c;
        }
    }
    return result;
}

std::string wrap_sanitize(const std::string &value) {
    return sanitize(value);
}

// [NO FLOW EXPECTED] Sanitizer applied
void interprocedural_kill_direct(const std::string &user_input) {
    std::string clean = sanitize(user_input);
    std::string query = "SELECT * FROM t WHERE x = '" + clean + "'";
    std::system(query.c_str());
}

// [NO FLOW EXPECTED] Sanitizer 2 levels deep
void interprocedural_kill_two_levels(const std::string &user_input) {
    std::string clean = wrap_sanitize(user_input);
    std::string query = "SELECT * FROM t WHERE x = '" + clean + "'";
    std::system(query.c_str());
}

// [FLOW EXPECTED] No sanitizer
void interprocedural_no_kill(const std::string &user_input) {
    std::string query = "SELECT * FROM t WHERE x = '" + user_input + "'";
    std::system(query.c_str());
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

struct Config {
    std::string command;
    std::string label;
};

// [FLOW EXPECTED] Tainted field flows to sink
void field_sensitive_tainted(const std::string &user_input) {
    Config cfg{user_input, "safe_label"};
    std::system(cfg.command.c_str());
}

// [NO FLOW EXPECTED] Only safe field used
void field_sensitive_safe(const std::string &user_input) {
    Config cfg{user_input, "safe_label"};
    std::system(cfg.label.c_str());
}

// [NO FLOW EXPECTED] Tainted field overwritten
void field_sensitive_overwrite(const std::string &user_input) {
    Config cfg{user_input, ""};
    cfg.command = "hardcoded_safe";
    std::system(cfg.command.c_str());
}


// ---------------------------------------------------------------------------
// 4. EXCEPTION CHAIN TAINT (C++-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through exception
void exception_taint(const std::string &user_input) {
    try {
        throw std::runtime_error("Invalid: " + user_input);
    } catch (const std::exception &e) {
        std::system(e.what()); // tainted
    }
}


// ---------------------------------------------------------------------------
// 5. VIRTUAL DISPATCH (polymorphism)
// ---------------------------------------------------------------------------

class Executor {
public:
    virtual ~Executor() = default;
    virtual void execute(const std::string &cmd) = 0;
};

class SafeExecutor : public Executor {
public:
    void execute(const std::string &cmd) override {
        std::cout << "Would execute: " << cmd << std::endl; // safe
    }
};

class UnsafeExecutor : public Executor {
public:
    void execute(const std::string &cmd) override {
        std::system(cmd.c_str()); // dangerous
    }
};

// [FLOW EXPECTED]
void type_tracked_unsafe(const std::string &user_input) {
    std::unique_ptr<Executor> executor = std::make_unique<UnsafeExecutor>();
    executor->execute(user_input);
}

// [NO FLOW EXPECTED]
void type_tracked_safe(const std::string &user_input) {
    std::unique_ptr<Executor> executor = std::make_unique<SafeExecutor>();
    executor->execute(user_input);
}


// ---------------------------------------------------------------------------
// 6. SMART POINTER CHAIN
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through smart pointer chain
void smart_pointer_taint(const std::string &user_input) {
    auto ptr = std::make_unique<std::string>(user_input);
    auto shared = std::make_shared<std::string>(*ptr);
    std::system(shared->c_str());
}


// ---------------------------------------------------------------------------
// 7. LAMBDA CAPTURE TAINT
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Lambda captures tainted value by reference
void lambda_capture_taint(const std::string &user_input) {
    auto process = [&user_input]() {
        std::system(user_input.c_str());
    };
    process();
}


// ---------------------------------------------------------------------------
// 8. OPTIONAL CHAIN
// ---------------------------------------------------------------------------

std::optional<std::string> parse_input(const std::string &input) {
    return input;
}

// [FLOW EXPECTED] Taint flows through optional
void optional_taint(const std::string &user_input) {
    auto cmd = parse_input(user_input).value_or("default");
    std::system(cmd.c_str());
}


// ---------------------------------------------------------------------------
// 9. STRUCTURED BINDINGS
// ---------------------------------------------------------------------------

std::pair<std::string, int> fetch_data(const std::string &source) {
    return {source, 0};
}

// [FLOW EXPECTED] First element carries taint
void structured_binding_tainted(const std::string &user_input) {
    auto [data, status] = fetch_data(user_input);
    std::system(data.c_str());
}


// ---------------------------------------------------------------------------
// 10. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] External entry point
void handle_webhook(const std::string &payload, const std::string &signature) {
    std::system(("process " + payload).c_str());
}


// ---------------------------------------------------------------------------
// 11. CROSS-METHOD CLASS FIELD TAINT
// ---------------------------------------------------------------------------

class Pipeline {
    std::string data_;
public:
    void ingest(const std::string &raw) {
        data_ = raw;
    }

    void process() {
        std::system(data_.c_str());
    }
};

// [FLOW EXPECTED]
void cross_method_field_taint(const std::string &user_input) {
    Pipeline p;
    p.ingest(user_input);
    p.process();
}


// ---------------------------------------------------------------------------
// 12. MOVE SEMANTICS
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint survives std::move
void move_taint(const std::string &user_input) {
    std::string cmd = user_input;
    std::string moved_cmd = std::move(cmd);
    std::system(moved_cmd.c_str());
}


// ---------------------------------------------------------------------------
// 13. VARIANT DISPATCH
// ---------------------------------------------------------------------------

using CommandVariant = std::variant<std::string, int>;

// [FLOW EXPECTED] Taint through variant
void variant_taint(const std::string &user_input) {
    CommandVariant cmd = user_input;
    if (auto *s = std::get_if<std::string>(&cmd)) {
        std::system(s->c_str());
    }
}
