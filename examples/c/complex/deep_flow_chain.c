/* deep_flow_chain.c -- Entry point reading user input through a
 * processing pipeline.
 *
 * Flow: fgets -> parse -> validate -> transform -> registry -> executor -> system()
 * 30+ steps across 3 files, 5+ function calls deep.
 *
 * Uses "Dfc" prefix on all types. Standard library only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "deep_flow_chain.h"

/* Step 1: Read raw user input from stdin */
static void dfc_read_user_input(struct DfcRawInput *raw) {
    printf("Enter command> ");
    /* SOURCE: fgets reads tainted data */
    if (fgets(raw->line, sizeof(raw->line), stdin) == NULL) {
        raw->line[0] = '\0';
    }
    /* Step 2: Strip trailing newline */
    size_t len = strlen(raw->line);
    if (len > 0 && raw->line[len - 1] == '\n') {
        raw->line[len - 1] = '\0';
    }
    raw->timestamp = 1234567890;
}

/* Step 3-5: Tokenize the raw input line */
static void dfc_tokenize(const struct DfcRawInput *raw, struct DfcTokenSet *tokens) {
    /* Step 3: Copy line for tokenization */
    char buf[1024];
    strncpy(buf, raw->line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Step 4: Split on whitespace */
    tokens->count = 0;
    char *tok = strtok(buf, " \t");
    while (tok != NULL && tokens->count < 32) {
        strncpy(tokens->parts[tokens->count], tok, 127);
        tokens->parts[tokens->count][127] = '\0';
        tokens->count++;
        tok = strtok(NULL, " \t");
    }
    /* Step 5: Token set is now populated */
}

/* Step 6-9: Build parsed command from tokens */
static void dfc_build_parsed_command(const struct DfcTokenSet *tokens,
                                     const char *raw_line,
                                     struct DfcParsedCommand *cmd) {
    memset(cmd, 0, sizeof(*cmd));

    /* Step 6: Extract verb from first token */
    if (tokens->count > 0) {
        strncpy(cmd->verb, tokens->parts[0], sizeof(cmd->verb) - 1);
    }

    /* Step 7: Extract target from second token */
    if (tokens->count > 1) {
        strncpy(cmd->target, tokens->parts[1], sizeof(cmd->target) - 1);
    }

    /* Step 8: Remaining tokens become options */
    cmd->options[0] = '\0';
    for (int i = 2; i < tokens->count; i++) {
        if (i > 2) {
            strncat(cmd->options, " ", sizeof(cmd->options) - strlen(cmd->options) - 1);
        }
        strncat(cmd->options, tokens->parts[i],
                sizeof(cmd->options) - strlen(cmd->options) - 1);
    }

    /* Step 9: Store original raw line */
    strncpy(cmd->raw_line, raw_line, sizeof(cmd->raw_line) - 1);
}

/* Step 10: Normalize verb to lowercase */
static void dfc_normalize_verb(struct DfcParsedCommand *cmd) {
    for (int i = 0; cmd->verb[i]; i++) {
        if (cmd->verb[i] >= 'A' && cmd->verb[i] <= 'Z') {
            cmd->verb[i] = cmd->verb[i] + 32;
        }
    }
}

/* Step 11: Attach trace metadata to options */
static void dfc_attach_metadata(struct DfcParsedCommand *cmd) {
    strncat(cmd->options, " --trace-id=42",
            sizeof(cmd->options) - strlen(cmd->options) - 1);
}

int main(void) {
    struct DfcRawInput raw;
    struct DfcTokenSet tokens;
    struct DfcParsedCommand cmd;
    struct DfcCommandRegistry registry;
    struct DfcExecConfig config;

    /* Steps 1-2: Read user input */
    dfc_read_user_input(&raw);

    /* Steps 3-5: Tokenize */
    dfc_tokenize(&raw, &tokens);

    /* Steps 6-9: Parse into command */
    dfc_build_parsed_command(&tokens, raw.line, &cmd);

    /* Step 10: Normalize */
    dfc_normalize_verb(&cmd);

    /* Step 11: Attach metadata */
    dfc_attach_metadata(&cmd);

    /* Steps 12-16: Validate (cross-file, deep_flow_helpers.c) */
    if (!dfc_validate(&cmd)) {
        fprintf(stderr, "Validation failed\n");
        return 1;
    }

    /* Steps 17-22: Transform (cross-file, deep_flow_helpers.c) */
    dfc_transform(&cmd);

    /* Steps 23-28: Register and resolve (cross-file, deep_flow_helpers.c) */
    dfc_registry_init(&registry);
    dfc_registry_register(&registry, &cmd);
    const char *command_str = dfc_registry_resolve(&registry, cmd.verb);

    /* Steps 29-35: Execute (cross-file, deep_flow_sink.c) */
    dfc_executor_init(&config);
    struct DfcExecResult result = dfc_executor_run(command_str, "production", &config);

    printf("Result (exit %d): %s\n", result.exit_code, result.output);
    return 0;
}
