/*
 * advanced_patterns.c - C-specific vulnerability patterns
 *
 * Self-contained file exercising function pointers, nested structs,
 * double pointers, variadic functions, goto, memcpy relays,
 * static buffers, typedef dispatch tables, and callback registration.
 *
 * Sources: fgets(stdin), getenv(), argv[], function parameters
 * Sinks:   system(), popen(), execvp(), sprintf()+system(), fopen()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define CMD_BUF 512
#define PATH_BUF 256
#define LOG_BUF 1024
#define MAX_HANDLERS 16

/* ---------- Structures ---------- */

/* Nested struct for chain 2 */
struct db_credentials {
    char host[128];
    char port[8];
    char query[256];
};

struct service_config {
    char name[64];
    struct db_credentials db;
};

struct deployment {
    char env_name[64];
    struct service_config primary;
    struct service_config fallback;
};

/* ---------- VULN 1: Function pointer dispatch ----------
 *
 * Chain: fgets(stdin) -> user_input -> dispatch via function pointer array
 *        -> execute_shell_action() -> sprintf() -> system()
 *
 * The taint flows through an array of function pointers indexed by
 * user-controlled input. The selected handler passes the tainted
 * string directly to system().
 */

typedef void (*action_handler_t)(const char *arg);

void execute_shell_action(const char *arg) {
    char cmd[CMD_BUF];
    sprintf(cmd, "action-runner --exec %s", arg);
    /* VULN: tainted arg reaches system() via sprintf */
    system(cmd);
}

void execute_status_action(const char *arg) {
    char cmd[CMD_BUF];
    sprintf(cmd, "action-runner --status %s", arg);
    system(cmd);
}

void execute_log_action(const char *arg) {
    char cmd[CMD_BUF];
    sprintf(cmd, "logger --tag %s", arg);
    system(cmd);
}

static action_handler_t action_table[] = {
    execute_shell_action,
    execute_status_action,
    execute_log_action,
};

void dispatch_by_index(int index, const char *arg) {
    if (index >= 0 && index < 3) {
        action_table[index](arg);
    }
}

void vuln_function_pointer_dispatch(void) {
    char user_input[256];
    printf("Enter action argument: ");
    fgets(user_input, sizeof(user_input), stdin);
    user_input[strcspn(user_input, "\n")] = '\0';
    /* VULN: user_input flows through function pointer to system() */
    dispatch_by_index(0, user_input);
}

/* ---------- VULN 2: Nested struct field chain ----------
 *
 * Chain: getenv("DEPLOY_QUERY") -> deployment.primary.db.query
 *        -> extract_query_from_deployment() -> build_db_command()
 *        -> sprintf() -> system()
 *
 * Taint propagates through nested struct field access across
 * three levels of struct nesting.
 */

void populate_deployment(struct deployment *deploy) {
    const char *env_query = getenv("DEPLOY_QUERY");
    if (env_query) {
        strncpy(deploy->primary.db.query, env_query,
                sizeof(deploy->primary.db.query) - 1);
    }
    strncpy(deploy->primary.db.host, "db.internal", 127);
    strncpy(deploy->primary.db.port, "5432", 7);
    strncpy(deploy->env_name, "production", 63);
}

const char *extract_query_from_deployment(struct deployment *deploy) {
    return deploy->primary.db.query;
}

void build_db_command(const char *query) {
    char cmd[CMD_BUF];
    sprintf(cmd, "psql -c \"%s\"", query);
    /* VULN: tainted query from nested struct reaches system() */
    system(cmd);
}

void vuln_nested_struct_chain(void) {
    struct deployment deploy;
    memset(&deploy, 0, sizeof(deploy));
    populate_deployment(&deploy);
    const char *query = extract_query_from_deployment(&deploy);
    build_db_command(query);
}

/* ---------- VULN 3: Multi-hop sprintf chain ----------
 *
 * Chain: getenv("USER_SCRIPT") -> base_script -> sprintf(step1)
 *        -> sprintf(step2) -> sprintf(final_cmd) -> system()
 *
 * Each sprintf appends more context around the tainted value,
 * but the taint survives through all three formatting hops.
 */

void vuln_sprintf_chain(void) {
    const char *base_script = getenv("USER_SCRIPT");
    if (!base_script) return;

    char step1[CMD_BUF];
    sprintf(step1, "/bin/sh -c '%s'", base_script);

    char step2[CMD_BUF];
    sprintf(step2, "timeout 30 %s", step1);

    char final_cmd[CMD_BUF];
    sprintf(final_cmd, "nice -n 10 %s 2>&1", step2);

    /* VULN: original getenv taint survives three sprintf hops */
    system(final_cmd);
}

/* ---------- VULN 4: Double pointer (char**) ----------
 *
 * Chain: fgets(stdin) -> raw_input -> parse_double_ptr(char**)
 *        -> *out_ptr set to tainted string -> sprintf() -> popen()
 *
 * Taint flows through a char** output parameter, a common C idiom
 * for returning allocated strings to callers.
 */

void parse_double_ptr(const char *raw, char **out_ptr) {
    *out_ptr = (char *)malloc(strlen(raw) + 1);
    if (*out_ptr) {
        strcpy(*out_ptr, raw);
    }
}

void vuln_double_pointer(void) {
    char raw_input[256];
    printf("Enter script path: ");
    fgets(raw_input, sizeof(raw_input), stdin);
    raw_input[strcspn(raw_input, "\n")] = '\0';

    char *parsed = NULL;
    parse_double_ptr(raw_input, &parsed);
    if (!parsed) return;

    char cmd[CMD_BUF];
    sprintf(cmd, "bash %s", parsed);
    /* VULN: tainted string from char** output parameter reaches popen() */
    FILE *proc = popen(cmd, "r");
    if (proc) {
        char result[256];
        while (fgets(result, sizeof(result), proc)) {
            printf("%s", result);
        }
        pclose(proc);
    }
    free(parsed);
}

/* ---------- VULN 5: Typedef handler dispatch table ----------
 *
 * Chain: fgets(stdin) -> command_line -> lookup in dispatch_table[]
 *        -> matched handler invoked -> process_deploy_command()
 *        -> sprintf() -> system()
 *
 * A named dispatch table (array of structs with name + function pointer)
 * routes user input to vulnerable handlers.
 */

typedef void (*cmd_handler_fn)(const char *args);

struct dispatch_entry {
    const char *name;
    cmd_handler_fn handler;
};

void process_deploy_command(const char *args) {
    char cmd[CMD_BUF];
    sprintf(cmd, "deploy-tool %s", args);
    /* VULN: tainted args from dispatch table reach system() */
    system(cmd);
}

void process_rollback_command(const char *args) {
    char cmd[CMD_BUF];
    sprintf(cmd, "rollback-tool %s", args);
    system(cmd);
}

static struct dispatch_entry dispatch_table[] = {
    {"deploy",   process_deploy_command},
    {"rollback", process_rollback_command},
    {NULL, NULL}
};

void execute_from_dispatch_table(const char *command, const char *args) {
    for (int i = 0; dispatch_table[i].name != NULL; i++) {
        if (strcmp(command, dispatch_table[i].name) == 0) {
            dispatch_table[i].handler(args);
            return;
        }
    }
}

void vuln_typedef_dispatch(void) {
    char command_line[512];
    printf("Enter command (deploy/rollback) and args: ");
    fgets(command_line, sizeof(command_line), stdin);
    command_line[strcspn(command_line, "\n")] = '\0';

    char *space = strchr(command_line, ' ');
    if (!space) return;
    *space = '\0';
    const char *cmd_name = command_line;
    const char *cmd_args = space + 1;

    /* VULN: cmd_args from fgets flows through dispatch table to system() */
    execute_from_dispatch_table(cmd_name, cmd_args);
}

/* ---------- VULN 6: memcpy relay ----------
 *
 * Chain: fgets(stdin) -> source_buf -> memcpy(relay1) -> memcpy(relay2)
 *        -> sprintf() -> system()
 *
 * Taint propagates through two memcpy calls, each copying the
 * tainted buffer into a new location before it reaches the sink.
 */

void relay_via_memcpy(const char *source, char *dest, int len) {
    memcpy(dest, source, len);
}

void vuln_memcpy_relay(void) {
    char source_buf[256];
    printf("Enter relay data: ");
    fgets(source_buf, sizeof(source_buf), stdin);
    source_buf[strcspn(source_buf, "\n")] = '\0';

    int len = strlen(source_buf) + 1;
    char relay1[256];
    relay_via_memcpy(source_buf, relay1, len);

    char relay2[256];
    relay_via_memcpy(relay1, relay2, len);

    char cmd[CMD_BUF];
    sprintf(cmd, "processor --input %s", relay2);
    /* VULN: taint survives two memcpy hops to reach system() */
    system(cmd);
}

/* ---------- VULN 7: Static/global buffer relay ----------
 *
 * Chain: getenv("PLUGIN_PATH") -> store_in_global_buffer()
 *        -> global g_plugin_path -> retrieve_from_global_buffer()
 *        -> sprintf() -> fopen()
 *
 * Taint flows into a static global buffer and is later retrieved
 * by a separate function that uses it in a file open.
 */

static char g_plugin_path[PATH_BUF];

void store_in_global_buffer(const char *path) {
    strncpy(g_plugin_path, path, PATH_BUF - 1);
    g_plugin_path[PATH_BUF - 1] = '\0';
}

const char *retrieve_from_global_buffer(void) {
    return g_plugin_path;
}

void vuln_static_buffer_relay(void) {
    const char *plugin = getenv("PLUGIN_PATH");
    if (!plugin) return;

    store_in_global_buffer(plugin);
    const char *stored = retrieve_from_global_buffer();

    char full_path[PATH_BUF];
    sprintf(full_path, "/opt/plugins/%s/init.so", stored);
    /* VULN: tainted getenv value stored in global reaches fopen() */
    FILE *fp = fopen(full_path, "rb");
    if (fp) {
        printf("Plugin loaded from: %s\n", full_path);
        fclose(fp);
    }
}

/* ---------- VULN 8: Variadic function (format string) ----------
 *
 * Chain: fgets(stdin) -> user_msg -> log_message(fmt, ...) with
 *        user_msg embedded -> vsprintf() -> resulting buffer
 *        used in system() call for remote logging
 *
 * A variadic logging function accepts a format string that includes
 * user-controlled content, building a command for remote log shipping.
 */

void log_and_ship(const char *fmt, ...) {
    char log_line[LOG_BUF];
    va_list args;
    va_start(args, fmt);
    vsprintf(log_line, fmt, args);
    va_end(args);

    char cmd[CMD_BUF];
    sprintf(cmd, "log-shipper --msg \"%s\"", log_line);
    /* VULN: variadic args containing user input reach system() */
    system(cmd);
}

void vuln_variadic_function(void) {
    char user_msg[256];
    printf("Enter log message: ");
    fgets(user_msg, sizeof(user_msg), stdin);
    user_msg[strcspn(user_msg, "\n")] = '\0';

    /* VULN: user_msg flows through vsprintf in variadic function to system() */
    log_and_ship("User submitted: %s at timestamp %d", user_msg, 1700000000);
}

/* ---------- VULN 9: goto control flow ----------
 *
 * Chain: fgets(stdin) -> filename -> goto skip_validation
 *        -> sprintf(path) -> fopen()
 *
 * Taint survives a goto jump that skips over potential validation
 * logic, reaching a path-traversal-vulnerable fopen().
 */

void vuln_goto_control_flow(int skip_check) {
    char filename[256];
    printf("Enter filename: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = '\0';

    if (skip_check) {
        goto open_file;
    }

    /* This validation is skipped when goto fires */
    for (int i = 0; filename[i]; i++) {
        if (filename[i] == '/' || filename[i] == '\\') {
            printf("Invalid filename\n");
            return;
        }
    }

open_file:
    ;
    char path[PATH_BUF];
    sprintf(path, "/var/data/%s", filename);
    /* VULN: tainted filename survives goto, reaches fopen() */
    FILE *fp = fopen(path, "r");
    if (fp) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) {
            printf("%s", buf);
        }
        fclose(fp);
    }
}

/* ---------- VULN 10: Callback registration ----------
 *
 * Chain: fgets(stdin) -> payload -> register_callback(fn, payload)
 *        -> stored in callback_registry -> fire_callbacks()
 *        -> registered handler invoked with stored payload
 *        -> execute_registered_command() -> sprintf() -> system()
 *
 * A function pointer and its associated data are stored in a registry.
 * When callbacks fire later, the tainted payload is passed to the
 * stored handler which calls system().
 */

typedef void (*callback_fn)(const char *data);

struct callback_entry {
    callback_fn fn;
    char data[256];
    int active;
};

static struct callback_entry callback_registry[MAX_HANDLERS];
static int callback_count = 0;

void register_callback(callback_fn fn, const char *data) {
    if (callback_count >= MAX_HANDLERS) return;
    callback_registry[callback_count].fn = fn;
    strncpy(callback_registry[callback_count].data, data, 255);
    callback_registry[callback_count].data[255] = '\0';
    callback_registry[callback_count].active = 1;
    callback_count++;
}

void fire_callbacks(void) {
    for (int i = 0; i < callback_count; i++) {
        if (callback_registry[i].active && callback_registry[i].fn) {
            callback_registry[i].fn(callback_registry[i].data);
        }
    }
}

void execute_registered_command(const char *data) {
    char cmd[CMD_BUF];
    sprintf(cmd, "task-runner %s", data);
    /* VULN: stored tainted data from callback registry reaches system() */
    system(cmd);
}

void vuln_callback_registration(void) {
    char payload[256];
    printf("Enter task payload: ");
    fgets(payload, sizeof(payload), stdin);
    payload[strcspn(payload, "\n")] = '\0';

    /* VULN: payload registered as callback data, later invoked via system() */
    register_callback(execute_registered_command, payload);
    fire_callbacks();
}

/* ---------- VULN 11 (bonus): argv command injection ----------
 *
 * Chain: argv[1] -> target_host -> sprintf() -> popen()
 *
 * Direct flow from command-line argument to command execution
 * via popen, a common C pattern for scripting wrappers.
 */

void vuln_argv_injection(int argc, char *argv[]) {
    if (argc < 2) return;
    const char *target_host = argv[1];

    char cmd[CMD_BUF];
    sprintf(cmd, "ping -c 4 %s", target_host);
    /* VULN: argv[1] directly in popen() command */
    FILE *proc = popen(cmd, "r");
    if (proc) {
        char line[256];
        while (fgets(line, sizeof(line), proc)) {
            printf("%s", line);
        }
        pclose(proc);
    }
}

/* ---------- VULN 12 (bonus): execvp with tainted argv ----------
 *
 * Chain: getenv("BACKUP_TARGET") -> target -> build argv array
 *        -> execvp()
 *
 * Tainted environment variable placed directly into an argv array
 * and passed to execvp.
 */

void vuln_execvp_tainted_argv(void) {
    const char *target = getenv("BACKUP_TARGET");
    if (!target) return;

    char target_buf[256];
    strncpy(target_buf, target, sizeof(target_buf) - 1);
    target_buf[sizeof(target_buf) - 1] = '\0';

    char *exec_argv[] = {"rsync", "-avz", "/data/", target_buf, NULL};
    /* VULN: tainted getenv in argv array reaches execvp() */
    execvp("rsync", exec_argv);
}

/* ---------- Entry point for testing ---------- */

int main(int argc, char *argv[]) {
    printf("=== Advanced C Pattern Tests ===\n\n");

    /* Each vuln function demonstrates a distinct pattern */
    vuln_function_pointer_dispatch();
    vuln_nested_struct_chain();
    vuln_sprintf_chain();
    vuln_double_pointer();
    vuln_typedef_dispatch();
    vuln_memcpy_relay();
    vuln_static_buffer_relay();
    vuln_variadic_function();
    vuln_goto_control_flow(1);
    vuln_callback_registration();
    vuln_argv_injection(argc, argv);
    vuln_execvp_tainted_argv();

    return 0;
}

/* ============================================================
 * ADDITIONAL PATTERNS - Signal handlers, variadic, unions
 * ============================================================ */

/* Signal handler with global taint */
static char g_command[256];

void signal_handler(int sig) {
    system(g_command);  /* taint from global in signal context */
}

void setup_signal(const char *input) {
    strncpy(g_command, input, sizeof(g_command) - 1);
    signal(SIGUSR1, signal_handler);
}

/* Union type confusion */
typedef union {
    char *command;
    int code;
} CommandData;

void union_flow(const char *input) {
    CommandData data;
    data.command = (char *)input;
    system(data.command);  /* taint through union */
}

/* Variadic function chain */
void exec_all(int count, ...) {
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        char *cmd = va_arg(args, char *);
        system(cmd);  /* taint through variadic */
    }
    va_end(args);
}

/* Struct with function pointer dispatch */
typedef struct {
    void (*execute)(const char *);
    const char *name;
} Handler;

void unsafe_exec(const char *cmd) { system(cmd); }

void dispatch_flow(const char *input) {
    Handler h = { .execute = unsafe_exec, .name = "cmd" };
    h.execute(input);  /* taint through function pointer */
}
