/* deep_flow_sink.cpp -- Final stage: format and execute the command.
 * Tainted user input reaches system()/popen() after full pipeline.
 * All names prefixed with Dfc.
 */

#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <array>

/* Shared class definition */
class DfcExecutionContext {
public:
    std::string formatted_command;
    std::string working_dir;
    int timeout_sec;
    bool dry_run;
    DfcExecutionContext() : timeout_sec(60), dry_run(false) {}
};

/* Steps 15-17: DfcCommandFormatter -- wraps command for shell */
class DfcCommandFormatter {
private:
    static void add_timeout(DfcExecutionContext *ctx) {
        ctx->formatted_command = "timeout " +
            std::to_string(ctx->timeout_sec) + " " +
            ctx->formatted_command;
    }
    static void add_dir_prefix(DfcExecutionContext *ctx) {
        ctx->formatted_command = "cd " + ctx->working_dir +
            " && " + ctx->formatted_command;
    }
    static void add_shell_wrapper(DfcExecutionContext *ctx) {
        ctx->formatted_command = "/bin/sh -c \"" +
            ctx->formatted_command + "\"";
    }
public:
    static bool format(DfcExecutionContext *ctx) {
        if (ctx->formatted_command.empty()) return false;
        add_timeout(ctx);
        add_dir_prefix(ctx);
        add_shell_wrapper(ctx);
        return true;
    }
};

/* Steps 18-20: DfcPipelineExecutor -- runs the command */
class DfcPipelineExecutor {
private:
    static int execute_captured(const std::string &command) {
        /* SINK: tainted data reaches popen() */
        FILE *proc = popen(command.c_str(), "r");
        if (!proc) return -1;
        std::array<char, 256> buffer;
        while (fgets(buffer.data(), buffer.size(), proc) != nullptr) {
            std::cout << "[OUTPUT] " << buffer.data();
        }
        return pclose(proc);
    }
    static int execute_direct(const std::string &command) {
        /* SINK: tainted data reaches system() */
        int result = system(command.c_str());
        return result;
    }
public:
    static int execute(DfcExecutionContext *ctx) {
        if (ctx->dry_run) {
            std::cout << "[DRY RUN] " << ctx->formatted_command << std::endl;
            return 0;
        }
        int result = execute_captured(ctx->formatted_command);
        if (result != 0) {
            result = execute_direct(ctx->formatted_command);
        }
        return result;
    }
};
