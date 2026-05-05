/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * 1. BRANCH-AWARE KILL ANALYSIS
 * ------------------------------------------------------------------------- */

/* [NO FLOW EXPECTED] Both branches sanitize */
void branch_kill_both_paths(const char *user_input) {
    const char *cmd;
    if (strlen(user_input) > 100) {
        cmd = "default_command";
    } else {
        cmd = "safe_fallback";
    }
    system(cmd); /* safe: both paths overwrite cmd */
}

/* [FLOW EXPECTED] Only one branch kills taint */
void branch_kill_one_path(char *user_input) {
    char *cmd = user_input;
    if (strlen(cmd) > 100) {
        cmd = "truncated";
    }
    /* else: cmd still holds user_input */
    system(cmd); /* tainted */
}


/* -------------------------------------------------------------------------
 * 2. INTERPROCEDURAL KILL (2+ levels deep)
 * ------------------------------------------------------------------------- */

static char *sanitize(const char *value, char *buf, size_t buflen) {
    size_t j = 0;
    for (size_t i = 0; value[i] && j < buflen - 1; i++) {
        if (value[i] != '\'' && value[i] != ';') {
            buf[j++] = value[i];
        }
    }
    buf[j] = '\0';
    return buf;
}

static char *wrap_sanitize(const char *value, char *buf, size_t buflen) {
    return sanitize(value, buf, buflen);
}

/* [NO FLOW EXPECTED] Sanitizer applied */
void interprocedural_kill_direct(const char *user_input) {
    char clean[256];
    sanitize(user_input, clean, sizeof(clean));
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM t WHERE x = '%s'", clean);
    system(query); /* safe */
}

/* [NO FLOW EXPECTED] Sanitizer 2 levels deep */
void interprocedural_kill_two_levels(const char *user_input) {
    char clean[256];
    wrap_sanitize(user_input, clean, sizeof(clean));
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM t WHERE x = '%s'", clean);
    system(query); /* safe */
}

/* [FLOW EXPECTED] No sanitizer */
void interprocedural_no_kill(const char *user_input) {
    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM t WHERE x = '%s'", user_input);
    system(query); /* tainted */
}


/* -------------------------------------------------------------------------
 * 3. FIELD-SENSITIVE TRACKING
 * ------------------------------------------------------------------------- */

struct Config {
    char command[256];
    char label[256];
};

/* [FLOW EXPECTED] Tainted field flows to sink */
void field_sensitive_tainted(const char *user_input) {
    struct Config cfg;
    strncpy(cfg.command, user_input, sizeof(cfg.command) - 1);
    strncpy(cfg.label, "safe_label", sizeof(cfg.label) - 1);
    system(cfg.command); /* tainted */
}

/* [NO FLOW EXPECTED] Only safe field used */
void field_sensitive_safe(const char *user_input) {
    struct Config cfg;
    strncpy(cfg.command, user_input, sizeof(cfg.command) - 1);
    strncpy(cfg.label, "safe_label", sizeof(cfg.label) - 1);
    system(cfg.label); /* safe */
}

/* [NO FLOW EXPECTED] Tainted field overwritten */
void field_sensitive_overwrite(const char *user_input) {
    struct Config cfg;
    strncpy(cfg.command, user_input, sizeof(cfg.command) - 1);
    strncpy(cfg.command, "hardcoded_safe", sizeof(cfg.command) - 1);
    system(cfg.command); /* safe: overwritten */
}


/* -------------------------------------------------------------------------
 * 4. OUTPUT PARAMETER TAINT (C-specific)
 * ------------------------------------------------------------------------- */

static void fetch_data(const char *source, char *out, size_t out_len) {
    strncpy(out, source, out_len - 1);
    out[out_len - 1] = '\0';
}

/* [FLOW EXPECTED] Output parameter carries taint */
void output_param_tainted(const char *user_input) {
    char buf[256];
    fetch_data(user_input, buf, sizeof(buf));
    system(buf); /* tainted: buf filled from user_input */
}


/* -------------------------------------------------------------------------
 * 5. FUNCTION POINTER DISPATCH
 * ------------------------------------------------------------------------- */

typedef void (*handler_fn)(const char *);

static void safe_handler(const char *cmd) {
    printf("Would execute: %s\n", cmd); /* safe */
}

static void unsafe_handler(const char *cmd) {
    system(cmd); /* dangerous */
}

/* [FLOW EXPECTED] Unsafe handler dispatched */
void function_ptr_unsafe(const char *user_input) {
    handler_fn handler = unsafe_handler;
    handler(user_input);
}

/* [NO FLOW EXPECTED] Safe handler dispatched */
void function_ptr_safe(const char *user_input) {
    handler_fn handler = safe_handler;
    handler(user_input);
}


/* -------------------------------------------------------------------------
 * 6. GLOBAL VARIABLE BRIDGE
 * ------------------------------------------------------------------------- */

static char g_command[256] = {0};

void set_global_command(const char *user_input) {
    strncpy(g_command, user_input, sizeof(g_command) - 1);
}

/* [FLOW EXPECTED] Taint flows through global variable */
void use_global_command(void) {
    system(g_command);
}


/* -------------------------------------------------------------------------
 * 7. SPRINTF CHAIN
 * ------------------------------------------------------------------------- */

/* [FLOW EXPECTED] Taint survives multi-hop sprintf */
void sprintf_chain(const char *user_input) {
    char buf1[256], buf2[512];
    sprintf(buf1, "cmd: %s", user_input);
    sprintf(buf2, "/bin/sh -c '%s'", buf1);
    system(buf2); /* tainted: chain preserves input */
}


/* -------------------------------------------------------------------------
 * 8. PARAMETER SOURCE SYNTHESIS
 * ------------------------------------------------------------------------- */

/* [FLOW EXPECTED] External entry point */
void handle_webhook(const char *payload, const char *signature) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "process %s", payload);
    system(cmd);
}


/* -------------------------------------------------------------------------
 * 9. MEMCPY TAINT RELAY
 * ------------------------------------------------------------------------- */

/* [FLOW EXPECTED] Taint flows through memcpy */
void memcpy_relay(const char *user_input) {
    char buf1[256];
    char buf2[256];
    memcpy(buf1, user_input, strlen(user_input) + 1);
    memcpy(buf2, buf1, strlen(buf1) + 1);
    system(buf2); /* tainted */
}


/* -------------------------------------------------------------------------
 * 10. ARRAY/CONTAINER ELEMENT
 * ------------------------------------------------------------------------- */

/* [FLOW EXPECTED] Tainted element in array */
void array_element_tainted(const char *user_input) {
    const char *commands[3];
    commands[0] = user_input;
    commands[1] = "ls";
    commands[2] = "pwd";
    system(commands[0]); /* tainted */
}

/* [NO FLOW EXPECTED] Safe element used after overwrite */
void array_element_overwrite(const char *user_input) {
    const char *commands[3];
    commands[0] = user_input;
    commands[0] = "safe_command";
    system(commands[0]); /* safe: overwritten */
}
