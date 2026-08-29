/* deep_flow_chain.h -- Shared declarations for deep flow chain example.
 * All types use "Dfc" prefix.
 */

#ifndef DFC_DEEP_FLOW_CHAIN_H
#define DFC_DEEP_FLOW_CHAIN_H

#include <stddef.h>

/* --- Core data structures --- */

struct DfcRawInput {
    char line[1024];
    unsigned long timestamp;
};

struct DfcTokenSet {
    char parts[32][128];
    int count;
};

struct DfcParsedCommand {
    char verb[128];
    char target[256];
    char options[512];
    char raw_line[1024];
};

struct DfcRegistryEntry {
    char verb[128];
    char executable_path[256];
    char full_command[1024];
};

struct DfcCommandRegistry {
    struct DfcRegistryEntry entries[16];
    int count;
};

struct DfcExecConfig {
    char shell[64];
    int timeout_sec;
};

struct DfcExecResult {
    char output[4096];
    int exit_code;
    char command[1024];
};

/* --- deep_flow_helpers.c --- */

int dfc_check_verb(struct DfcParsedCommand *cmd);
int dfc_check_target(struct DfcParsedCommand *cmd);
int dfc_validate(struct DfcParsedCommand *cmd);
void dfc_expand_paths(struct DfcParsedCommand *cmd);
void dfc_join_options(struct DfcParsedCommand *cmd);
void dfc_build_command_line(struct DfcParsedCommand *cmd);
void dfc_transform(struct DfcParsedCommand *cmd);
void dfc_registry_init(struct DfcCommandRegistry *reg);
void dfc_registry_register(struct DfcCommandRegistry *reg,
                           const struct DfcParsedCommand *cmd);
const char *dfc_registry_resolve(struct DfcCommandRegistry *reg,
                                 const char *verb);

/* --- deep_flow_sink.c --- */

void dfc_executor_init(struct DfcExecConfig *config);
struct DfcExecResult dfc_executor_run(const char *command,
                                      const char *environment,
                                      struct DfcExecConfig *config);

#endif /* DFC_DEEP_FLOW_CHAIN_H */
