/* deep_flow_chain.cpp -- Entry point: reads user command, dispatches.
 * Flow: cin/argv -> DfcBuilder -> DfcValidator -> DfcTransformer
 *       -> DfcContextBuilder -> DfcFormatter -> DfcExecutor
 * All names prefixed with Dfc.
 */

#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>

/* Forward declarations for classes in other files */
class DfcPipelineRequest;
class DfcExecutionContext;

class DfcRequestBuilder {
public:
    static DfcPipelineRequest *build(const std::string &raw,
                                     const std::string &verb,
                                     const std::string &target);
};

class DfcRequestValidator {
public:
    static bool validate(DfcPipelineRequest *req);
};

class DfcRequestTransformer {
public:
    static bool transform(DfcPipelineRequest *req);
};

class DfcContextBuilder {
public:
    static DfcExecutionContext *build(DfcPipelineRequest *req);
};

class DfcMiddlewareChain {
public:
    static bool apply(DfcExecutionContext *ctx, DfcPipelineRequest *req);
};

class DfcCommandFormatter {
public:
    static bool format(DfcExecutionContext *ctx);
};

class DfcPipelineExecutor {
public:
    static int execute(DfcExecutionContext *ctx);
};

/* Shared data structures */
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

static std::string dfc_read_input() {
    std::string input;
    std::getline(std::cin, input);
    return input;
}

static void dfc_split(const std::string &input,
                       std::string &verb, std::string &target) {
    std::istringstream iss(input);
    iss >> verb;
    std::getline(iss, target);
    size_t s = target.find_first_not_of(' ');
    if (s != std::string::npos) target = target.substr(s);
}

int main(int argc, char *argv[]) {
    std::string raw_input;
    if (argc > 1) {
        raw_input = argv[1];
        for (int i = 2; i < argc; i++) { raw_input += " "; raw_input += argv[i]; }
    } else {
        raw_input = dfc_read_input();
    }
    if (raw_input.empty()) return 1;

    std::string verb, target;
    dfc_split(raw_input, verb, target);

    DfcPipelineRequest *req = DfcRequestBuilder::build(raw_input, verb, target);
    req->parsed_command = verb + " " + target;
    if (!DfcRequestValidator::validate(req)) { delete req; return 1; }
    if (!DfcRequestTransformer::transform(req)) { delete req; return 1; }

    DfcExecutionContext *ctx = DfcContextBuilder::build(req);
    if (!ctx) { delete req; return 1; }
    if (!DfcMiddlewareChain::apply(ctx, req)) { delete ctx; delete req; return 1; }
    if (!DfcCommandFormatter::format(ctx)) { delete ctx; delete req; return 1; }

    int result = DfcPipelineExecutor::execute(ctx);
    delete ctx;
    delete req;
    return result;
}
