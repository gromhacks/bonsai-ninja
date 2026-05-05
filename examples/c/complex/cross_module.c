/*
 * cross_module.c - Cross-file vulnerability chains
 *
 * Exercises interprocedural flows spanning multiple existing C files:
 *   main.c, utils.c, utils.h, firmware.c, config.c, device_control.c
 *
 * Chain A: 10+ hops across 4 files (fgets -> parse -> extract -> config -> system)
 * Chain B: Global/static variable relay
 * Chain C: Callback/function pointer cross-module
 * Chain D: Re-exported wrapper chain
 * Chain E: Recursive chain
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#define XMOD_BUF 512

/* ---------- Extern declarations for cross-file references ---------- */

/* From config.c */
extern int config_set(const char *key, const char *value);
extern const char *config_get(const char *key);
extern void export_config(const char *format, const char *output_path);

/* From device_control.c */
extern void handle_device_command(int client_sock, const char *request);
extern struct device *find_device(const char *id);
extern int register_device(const char *id, const char *name, const char *type);

/* From firmware.c */
extern struct firmware_image *extract_firmware(const unsigned char *data, unsigned int size);
extern int apply_firmware_update(struct firmware_image *img);
extern void free_firmware_image(struct firmware_image *img);
extern int schedule_update(const char *cron_expr, const char *firmware_path);

/* From main.c */
extern int parse_http_request(const char *raw, struct http_request *req);
extern void execute_device_action(const char *device_id, const char *action);
extern int read_log_file(const char *filename, char *output, int output_size);

/* Need the http_request struct from main.c */
struct http_request {
    char method[16];
    char path[256];
    char body[4096];
    int body_length;
    char headers[1024];
};

/* ---------- CHAIN A: 10+ hops, 4 files ----------
 *
 * Flow: fgets(stdin)                              [cross_module.c - SOURCE]
 *   -> raw_request                                [cross_module.c]
 *   -> step_a_receive_request(raw)                [cross_module.c]
 *   -> parse_http_request(raw, &req)              [main.c - parses into req.body]
 *   -> step_a_extract_fields(req.body)            [cross_module.c]
 *   -> extract_json_field(body, "target", target) [utils.c - extracts JSON field]
 *   -> step_a_store_target(target)                [cross_module.c]
 *   -> config_set("scan_target", target)          [config.c - stores in config]
 *   -> step_a_build_scan()                        [cross_module.c]
 *   -> config_get("scan_target")                  [config.c - retrieves from config]
 *   -> step_a_format_command(target_val)           [cross_module.c]
 *   -> sprintf(cmd, "nmap %s", target_val)        [cross_module.c]
 *   -> system(cmd)                                [cross_module.c - SINK]
 *
 * 12 hops across cross_module.c, main.c, utils.c, config.c
 */

void step_a_extract_fields(const char *body, char *target, int target_size) {
    extract_json_field(body, "target", target, target_size);
}

void step_a_store_target(const char *target) {
    config_set("scan_target", target);
}

char *step_a_format_command(const char *target_val) {
    char *cmd = (char *)malloc(XMOD_BUF);
    if (!cmd) return NULL;
    sprintf(cmd, "nmap -sV %s", target_val);
    return cmd;
}

void step_a_build_scan(void) {
    const char *target_val = config_get("scan_target");
    if (!target_val) return;

    char *cmd = step_a_format_command(target_val);
    if (!cmd) return;

    /* VULN Chain A: user input from fgets traversed parse_http_request,
       extract_json_field, config_set/get, sprintf to reach system() */
    system(cmd);
    free(cmd);
}

void step_a_receive_request(const char *raw) {
    struct http_request req;
    parse_http_request(raw, &req);

    char target[256];
    step_a_extract_fields(req.body, target, sizeof(target));
    step_a_store_target(target);
    step_a_build_scan();
}

void vuln_chain_a_deep_cross_file(void) {
    char raw_request[4096];
    printf("Enter raw HTTP request: ");
    fgets(raw_request, sizeof(raw_request), stdin);
    raw_request[strcspn(raw_request, "\n")] = '\0';

    step_a_receive_request(raw_request);
}

/* ---------- CHAIN B: Global/static variable ----------
 *
 * Flow: getenv("CRON_SCHEDULE")                   [cross_module.c - SOURCE]
 *   -> cron_expr                                  [cross_module.c]
 *   -> store in g_scheduled_cron (global)         [cross_module.c]
 *   -> chain_b_apply_schedule()                   [cross_module.c]
 *   -> reads g_scheduled_cron                     [cross_module.c]
 *   -> schedule_update(g_scheduled_cron, path)    [firmware.c]
 *   -> sprintf(cmd, "crontab ... %s ...")         [firmware.c]
 *   -> system(cmd)                                [firmware.c - SINK]
 *
 * Taint stored in a global variable, retrieved by a different function,
 * and passed to firmware.c's schedule_update which calls system().
 */

static char g_scheduled_cron[256];
static char g_scheduled_firmware[256];

void chain_b_store_schedule(const char *cron, const char *firmware_path) {
    strncpy(g_scheduled_cron, cron, sizeof(g_scheduled_cron) - 1);
    g_scheduled_cron[sizeof(g_scheduled_cron) - 1] = '\0';
    strncpy(g_scheduled_firmware, firmware_path, sizeof(g_scheduled_firmware) - 1);
    g_scheduled_firmware[sizeof(g_scheduled_firmware) - 1] = '\0';
}

void chain_b_apply_schedule(void) {
    if (strlen(g_scheduled_cron) == 0) return;
    /* VULN Chain B: global variable carries taint from getenv to
       firmware.c schedule_update() -> sprintf() -> system() */
    schedule_update(g_scheduled_cron, g_scheduled_firmware);
}

void vuln_chain_b_global_variable(void) {
    const char *cron_expr = getenv("CRON_SCHEDULE");
    if (!cron_expr) return;

    chain_b_store_schedule(cron_expr, "/opt/firmware/latest.bin");
    chain_b_apply_schedule();
}

/* ---------- CHAIN C: Callback / function pointer cross-module ----------
 *
 * Flow: fgets(stdin)                              [cross_module.c - SOURCE]
 *   -> user_action                                [cross_module.c]
 *   -> register in handler table (fn ptr)         [cross_module.c]
 *   -> chain_c_fire_handler()                     [cross_module.c]
 *   -> handler(user_action) dispatched            [cross_module.c]
 *   -> chain_c_device_handler(action)             [cross_module.c]
 *   -> execute_device_action(device_id, action)   [main.c]
 *   -> sprintf(cmd, "device-ctl ... %s")          [main.c]
 *   -> system(cmd)                                [main.c - SINK]
 *
 * Taint flows through a stored function pointer into main.c's
 * execute_device_action which calls system().
 */

typedef void (*cross_handler_fn)(const char *data);

struct cross_handler_entry {
    cross_handler_fn handler;
    char payload[256];
    int registered;
};

static struct cross_handler_entry g_cross_handler = { .registered = 0 };

void chain_c_register_handler(cross_handler_fn fn, const char *data) {
    g_cross_handler.handler = fn;
    strncpy(g_cross_handler.payload, data, 255);
    g_cross_handler.payload[255] = '\0';
    g_cross_handler.registered = 1;
}

void chain_c_fire_handler(void) {
    if (g_cross_handler.registered && g_cross_handler.handler) {
        g_cross_handler.handler(g_cross_handler.payload);
    }
}

void chain_c_device_handler(const char *action) {
    /* VULN Chain C: tainted action from callback reaches
       main.c execute_device_action() -> system() */
    execute_device_action("device-001", action);
}

void vuln_chain_c_callback_cross_module(void) {
    char user_action[256];
    printf("Enter device action: ");
    fgets(user_action, sizeof(user_action), stdin);
    user_action[strcspn(user_action, "\n")] = '\0';

    chain_c_register_handler(chain_c_device_handler, user_action);
    chain_c_fire_handler();
}

/* ---------- CHAIN D: Re-exported wrapper ----------
 *
 * Flow: fgets(stdin)                              [cross_module.c - SOURCE]
 *   -> user_path                                  [cross_module.c]
 *   -> chain_d_normalize_path(user_path)          [cross_module.c]
 *   -> string_duplicate(user_path)                [utils.c - duplicates string]
 *   -> chain_d_read_via_wrapper(normalized)       [cross_module.c]
 *   -> read_log_file(normalized, output, size)    [main.c]
 *   -> sprintf(path, "/var/log/.../%s", filename) [main.c]
 *   -> fopen(path, "r")                           [main.c - SINK]
 *
 * Wrapper functions re-export functionality from other modules.
 * Taint passes through utils.c string_duplicate and main.c read_log_file.
 */

char *chain_d_normalize_path(const char *raw_path) {
    /* Wrapper around utils.c string_duplicate - does NOT sanitize */
    char *dup = string_duplicate(raw_path);
    if (dup) {
        string_trim(dup);
    }
    return dup;
}

int chain_d_read_via_wrapper(const char *normalized_path) {
    char output[4096];
    /* VULN Chain D: tainted path flows through utils.c string_duplicate,
       then to main.c read_log_file() -> sprintf() -> fopen() */
    int result = read_log_file(normalized_path, output, sizeof(output));
    if (result > 0) {
        printf("Log contents:\n%s\n", output);
    }
    return result;
}

void vuln_chain_d_reexported_wrapper(void) {
    char user_path[256];
    printf("Enter log filename: ");
    fgets(user_path, sizeof(user_path), stdin);
    user_path[strcspn(user_path, "\n")] = '\0';

    char *normalized = chain_d_normalize_path(user_path);
    if (!normalized) return;

    chain_d_read_via_wrapper(normalized);
    free(normalized);
}

/* ---------- CHAIN E: Recursive chain ----------
 *
 * Flow: getenv("CONFIG_EXPORT_FMT")               [cross_module.c - SOURCE]
 *   -> format_str                                  [cross_module.c]
 *   -> chain_e_resolve_alias(format_str, depth)    [cross_module.c - RECURSIVE]
 *   -> config_get("alias_<format>")                [config.c - resolves alias]
 *   -> chain_e_resolve_alias(resolved, depth-1)    [cross_module.c - recurse]
 *   -> ... (up to 3 levels)                        [cross_module.c]
 *   -> chain_e_do_export(resolved_format)           [cross_module.c]
 *   -> export_config(resolved_format, output_path)  [config.c]
 *   -> sprintf(cmd, "config-export --format %s")   [config.c]
 *   -> system(cmd)                                  [config.c - SINK]
 *
 * Taint flows through recursive alias resolution. Each level
 * checks if the format is an alias by querying config, and if so
 * recurses. The final resolved format reaches config.c export_config().
 */

const char *chain_e_resolve_alias(const char *format, int depth) {
    if (depth <= 0) return format;

    /* Check if format is an alias by looking up config */
    char alias_key[128];
    sprintf(alias_key, "alias_%s", format);
    const char *resolved = config_get(alias_key);

    if (resolved && strlen(resolved) > 0) {
        /* Recurse: alias points to another format (possibly another alias) */
        return chain_e_resolve_alias(resolved, depth - 1);
    }

    /* Not an alias, return as-is */
    return format;
}

void chain_e_do_export(const char *resolved_format) {
    /* VULN Chain E: recursively resolved format from getenv reaches
       config.c export_config() -> sprintf() -> system() */
    export_config(resolved_format, "/tmp/config_export.out");
}

void vuln_chain_e_recursive(void) {
    const char *format_str = getenv("CONFIG_EXPORT_FMT");
    if (!format_str) return;

    /* Pre-populate alias chain for demonstration:
       "custom" -> alias_custom = "extended"
       "extended" -> alias_extended = "json"
       "json" -> no alias, used directly */
    config_set("alias_custom", "extended");
    config_set("alias_extended", "json");

    const char *resolved = chain_e_resolve_alias(format_str, 3);
    chain_e_do_export(resolved);
}

/* ---------- Entry point ---------- */

int main(void) {
    printf("=== Cross-Module Chain Tests ===\n\n");

    vuln_chain_a_deep_cross_file();
    vuln_chain_b_global_variable();
    vuln_chain_c_callback_cross_module();
    vuln_chain_d_reexported_wrapper();
    vuln_chain_e_recursive();

    return 0;
}
