/* deep_flow_sink.c -- Final executor with dangerous sink.
 *
 * Receives resolved command strings and executes them via system().
 * The taint chain terminates here at system() and popen().
 *
 * All types use "Dfc" prefix. Standard library only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "deep_flow_chain.h"

/* Step 29: Initialize executor config */
void dfc_executor_init(struct DfcExecConfig *config) {
    strncpy(config->shell, "/bin/bash", sizeof(config->shell) - 1);
    config->shell[sizeof(config->shell) - 1] = '\0';
    config->timeout_sec = 60;
}

/* Step 30: Build environment prefix */
static void dfc_build_env_prefix(const char *environment, char *prefix,
                                 size_t prefix_sz) {
    if (strcmp(environment, "production") == 0) {
        prefix[0] = '\0';
    } else {
        snprintf(prefix, prefix_sz, "echo [%s] && ", environment);
    }
}

/* Step 31: Combine prefix with command */
static void dfc_combine_command(const char *prefix, const char *command,
                                char *full, size_t full_sz) {
    snprintf(full, full_sz, "%s%s", prefix, command);
}

/* Step 32: Wrap in shell invocation */
static void dfc_wrap_in_shell(const char *shell, const char *command,
                              char *wrapped, size_t wrapped_sz) {
    snprintf(wrapped, wrapped_sz, "%s -c '%s'", shell, command);
}

/* Step 33: Trim whitespace from command */
static void dfc_trim_command(char *command) {
    /* Trim leading whitespace */
    char *start = command;
    while (*start == ' ' || *start == '\t') {
        start++;
    }
    if (start != command) {
        memmove(command, start, strlen(start) + 1);
    }
    /* Trim trailing whitespace */
    size_t len = strlen(command);
    while (len > 0 && (command[len - 1] == ' ' || command[len - 1] == '\t')) {
        command[--len] = '\0';
    }
}

/* Step 34: Execute with popen and capture output */
static struct DfcExecResult dfc_execute_with_capture(const char *command) {
    struct DfcExecResult result;
    memset(&result, 0, sizeof(result));
    strncpy(result.command, command, sizeof(result.command) - 1);

    /* SINK: tainted data reaches popen() */
    FILE *proc = popen(command, "r");
    if (proc == NULL) {
        result.exit_code = -1;
        strncpy(result.output, "popen failed", sizeof(result.output) - 1);
        return result;
    }

    char line[256];
    result.output[0] = '\0';
    while (fgets(line, sizeof(line), proc) != NULL) {
        strncat(result.output, line,
                sizeof(result.output) - strlen(result.output) - 1);
    }

    result.exit_code = pclose(proc);
    return result;
}

/* Step 35: Execute with system() as fallback */
static struct DfcExecResult dfc_execute_direct(const char *command) {
    struct DfcExecResult result;
    memset(&result, 0, sizeof(result));
    strncpy(result.command, command, sizeof(result.command) - 1);

    /* SINK: tainted data reaches system() */
    result.exit_code = system(command);
    strncpy(result.output, "(direct execution)", sizeof(result.output) - 1);
    return result;
}

/* Steps 29-35: Main executor entry point */
struct DfcExecResult dfc_executor_run(const char *command,
                                      const char *environment,
                                      struct DfcExecConfig *config) {
    /* Step 30: Build environment prefix */
    char prefix[128];
    dfc_build_env_prefix(environment, prefix, sizeof(prefix));

    /* Step 31: Combine prefix with command */
    char full_command[1024];
    dfc_combine_command(prefix, command, full_command, sizeof(full_command));

    /* Step 32: Wrap in shell invocation */
    char wrapped[1024];
    dfc_wrap_in_shell(config->shell, full_command, wrapped, sizeof(wrapped));

    /* Step 33: Trim */
    dfc_trim_command(wrapped);

    printf("[EXEC] Running: %s\n", wrapped);

    /* Step 34: Try captured execution first */
    struct DfcExecResult result = dfc_execute_with_capture(wrapped);
    if (result.exit_code != 0) {
        /* Step 35: Fall back to direct execution */
        fprintf(stderr, "[WARN] Captured execution failed, trying direct\n");
        result = dfc_execute_direct(wrapped);
    }

    return result;
}
