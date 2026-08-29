/* deep_flow_helpers.c -- Middleware/helper functions.
 *
 * DfcValidator checks command structure (weak, no sanitization).
 * DfcTransformPipeline applies transformations preserving taint.
 * DfcCommandRegistry maps verbs to executable paths.
 *
 * All types use "Dfc" prefix. Standard library only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "deep_flow_chain.h"

/* --- Validation (Steps 12-16) --- */

/* Step 13: Check verb against allowed list */
int dfc_check_verb(struct DfcParsedCommand *cmd) {
    const char *allowed[] = {"run", "exec", "deploy", "build", "test", NULL};
    for (int i = 0; allowed[i] != NULL; i++) {
        if (strcmp(cmd->verb, allowed[i]) == 0) {
            return 1;
        }
    }
    /* Bug: returns 1 anyway -- allows everything through */
    return 1;
}

/* Step 14: Check target is non-empty (no sanitization) */
int dfc_check_target(struct DfcParsedCommand *cmd) {
    /* Step 15: No real sanitization, just length check */
    if (strlen(cmd->target) == 0) {
        return 0;
    }
    /* Step 16: Target passes through tainted */
    return 1;
}

/* Step 12: Validate the parsed command */
int dfc_validate(struct DfcParsedCommand *cmd) {
    if (!dfc_check_verb(cmd)) {
        return 0;
    }
    if (!dfc_check_target(cmd)) {
        return 0;
    }
    return 1;
}

/* --- Transform (Steps 17-22) --- */

/* Step 18: Expand tilde in target (tainted data preserved) */
void dfc_expand_paths(struct DfcParsedCommand *cmd) {
    char *tilde = strchr(cmd->target, '~');
    if (tilde != NULL) {
        char expanded[256];
        size_t prefix_len = (size_t)(tilde - cmd->target);
        snprintf(expanded, sizeof(expanded), "%.*s/home/user%s",
                 (int)prefix_len, cmd->target, tilde + 1);
        strncpy(cmd->target, expanded, sizeof(cmd->target) - 1);
        cmd->target[sizeof(cmd->target) - 1] = '\0';
    }
}

/* Step 19-20: Join options into target string */
void dfc_join_options(struct DfcParsedCommand *cmd) {
    /* Step 19: Read current target */
    char combined[512];
    /* Step 20: Append options to target */
    snprintf(combined, sizeof(combined), "%s %s", cmd->target, cmd->options);
    strncpy(cmd->target, combined, sizeof(cmd->target) - 1);
    cmd->target[sizeof(cmd->target) - 1] = '\0';
}

/* Step 21-22: Build full command line */
void dfc_build_command_line(struct DfcParsedCommand *cmd) {
    /* Step 21: Combine verb and target into raw_line */
    char full_line[1024];
    snprintf(full_line, sizeof(full_line), "%s %s", cmd->verb, cmd->target);
    /* Step 22: Store in raw_line for downstream use */
    strncpy(cmd->raw_line, full_line, sizeof(cmd->raw_line) - 1);
    cmd->raw_line[sizeof(cmd->raw_line) - 1] = '\0';
}

/* Step 17: Run all transforms */
void dfc_transform(struct DfcParsedCommand *cmd) {
    dfc_expand_paths(cmd);
    dfc_join_options(cmd);
    dfc_build_command_line(cmd);
}

/* --- Registry (Steps 23-28) --- */

/* Step 23: Initialize the command registry */
void dfc_registry_init(struct DfcCommandRegistry *reg) {
    memset(reg, 0, sizeof(*reg));
    reg->count = 0;
}

/* Step 24-26: Register a command in the registry */
void dfc_registry_register(struct DfcCommandRegistry *reg,
                           const struct DfcParsedCommand *cmd) {
    if (reg->count >= 16) {
        return;
    }
    struct DfcRegistryEntry *entry = &reg->entries[reg->count];

    /* Step 24: Copy verb */
    strncpy(entry->verb, cmd->verb, sizeof(entry->verb) - 1);
    entry->verb[sizeof(entry->verb) - 1] = '\0';

    /* Step 25: Build executable path (tainted verb embedded) */
    snprintf(entry->executable_path, sizeof(entry->executable_path),
             "/usr/bin/%s", cmd->verb);

    /* Step 26: Build full command string (tainted target embedded) */
    snprintf(entry->full_command, sizeof(entry->full_command),
             "%s %s", entry->executable_path, cmd->target);

    reg->count++;
}

/* Step 27-28: Resolve a verb to its full command string */
const char *dfc_registry_resolve(struct DfcCommandRegistry *reg,
                                 const char *verb) {
    /* Step 27: Look up entry by verb */
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->entries[i].verb, verb) == 0) {
            /* Step 28: Return the full command string (tainted) */
            return reg->entries[i].full_command;
        }
    }
    return verb;
}
