/* deep_flow_helpers.cpp -- Middleware: validation, transformation pipeline.
 * Tainted data flows through class members across methods.
 * All names prefixed with Dfc.
 */

#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>

/* Shared class definitions (same as deep_flow_chain.cpp) */
class DfcPipelineRequest {
public:
    std::string raw_input;
    std::string parsed_command;
    std::string verb;
    std::string target;
    bool validated;
    int auth_level;
    DfcPipelineRequest() : validated(false), auth_level(0) {}
};

class DfcExecutionContext {
public:
    std::string formatted_command;
    std::string working_dir;
    int timeout_sec;
    bool dry_run;
    DfcExecutionContext() : timeout_sec(60), dry_run(false) {}
};

/* Step 4: DfcRequestBuilder -- creates DfcPipelineRequest from raw input */
class DfcRequestBuilder {
public:
    static DfcPipelineRequest *build(const std::string &raw,
                                     const std::string &verb,
                                     const std::string &target) {
        DfcPipelineRequest *req = new DfcPipelineRequest();
        req->raw_input = raw;
        req->verb = verb;
        req->target = target;
        return req;
    }
};

/* Steps 5-7: DfcRequestValidator -- validates but does NOT sanitize */
class DfcRequestValidator {
private:
    static bool check_length(DfcPipelineRequest *req) {
        return !req->raw_input.empty() && req->raw_input.size() < 900;
    }
    static bool check_verb(DfcPipelineRequest *req) {
        const std::string allowed[] = {"run", "deploy", "exec", "build"};
        for (const auto &v : allowed) {
            if (req->verb == v) return true;
        }
        return false;
    }
public:
    static bool validate(DfcPipelineRequest *req) {
        if (!check_length(req)) return false;
        if (!check_verb(req)) return false;
        req->validated = true;
        req->auth_level = 1;
        return true;
    }
};

/* Steps 8-9: DfcRequestTransformer -- normalizes but preserves taint */
class DfcRequestTransformer {
private:
    static std::string normalize_ws(const std::string &input) {
        std::string result;
        bool last_space = false;
        for (char c : input) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!last_space) { result += ' '; last_space = true; }
            } else { result += c; last_space = false; }
        }
        return result;
    }
public:
    static bool transform(DfcPipelineRequest *req) {
        if (!req->validated) return false;
        req->parsed_command = normalize_ws(req->parsed_command);
        return true;
    }
};

/* Steps 10-12: DfcContextBuilder -- creates DfcExecutionContext */
class DfcContextBuilder {
public:
    static DfcExecutionContext *build(DfcPipelineRequest *req) {
        DfcExecutionContext *ctx = new DfcExecutionContext();
        ctx->formatted_command = req->parsed_command;
        ctx->working_dir = "/var/run/" + req->target;
        ctx->timeout_sec = 60;
        return ctx;
    }
};

/* Steps 13-14: DfcMiddlewareChain -- audit and env prepend */
class DfcMiddlewareChain {
public:
    static bool apply(DfcExecutionContext *ctx, DfcPipelineRequest *req) {
        ctx->formatted_command += " --audit-level=" +
                                  std::to_string(req->auth_level);
        std::string env = "PIPELINE_CMD=" + req->verb;
        ctx->formatted_command = env + " " + ctx->formatted_command;
        return true;
    }
};
