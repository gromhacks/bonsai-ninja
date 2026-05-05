#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "utils.h"

#define MAX_CONFIG_ENTRIES 128
#define KEY_LEN 64
#define VALUE_LEN 256

struct config_entry {
    char key[KEY_LEN];
    char value[VALUE_LEN];
};

struct config_store {
    struct config_entry entries[MAX_CONFIG_ENTRIES];
    int count;
    char filepath[256];
};

static struct config_store global_config = { .count = 0 };

/* Initialize config from file */
int config_init(const char *filepath) {
    strncpy(global_config.filepath, filepath, sizeof(global_config.filepath) - 1);
    FILE *fp = fopen(filepath, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp) && global_config.count < MAX_CONFIG_ENTRIES) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        struct config_entry *entry = &global_config.entries[global_config.count];
        strncpy(entry->key, line, KEY_LEN - 1);
        strncpy(entry->value, eq + 1, VALUE_LEN - 1);
        /* Strip newline */
        char *nl = strchr(entry->value, '\n');
        if (nl) *nl = '\0';
        global_config.count++;
    }
    fclose(fp);
    return 0;
}

/* Get config value by key */
const char *config_get(const char *key) {
    for (int i = 0; i < global_config.count; i++) {
        if (strcmp(global_config.entries[i].key, key) == 0) {
            return global_config.entries[i].value;
        }
    }
    return NULL;
}

/* Set config value */
int config_set(const char *key, const char *value) {
    for (int i = 0; i < global_config.count; i++) {
        if (strcmp(global_config.entries[i].key, key) == 0) {
            strncpy(global_config.entries[i].value, value, VALUE_LEN - 1);
            return 0;
        }
    }
    if (global_config.count >= MAX_CONFIG_ENTRIES) return -1;
    struct config_entry *entry = &global_config.entries[global_config.count];
    strncpy(entry->key, key, KEY_LEN - 1);
    strncpy(entry->value, value, VALUE_LEN - 1);
    global_config.count++;
    return 0;
}

/* Save config to file */
int config_save(void) {
    FILE *fp = fopen(global_config.filepath, "w");
    if (!fp) return -1;
    for (int i = 0; i < global_config.count; i++) {
        fprintf(fp, "%s=%s\n", global_config.entries[i].key, global_config.entries[i].value);
    }
    fclose(fp);
    return 0;
}

/* Handle config update from HTTP */
void handle_config_update(int client_sock, const char *request) {
    char key[64];
    char value[256];

    extract_json_field(request, "key", key, sizeof(key));
    extract_json_field(request, "value", value, sizeof(value));

    if (strlen(key) == 0) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"Missing key\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    config_set(key, value);
    config_save();

    /* VULN: Command injection via config reload */
    char cmd[256];
    sprintf(cmd, "config-reload --key %s", key);
    system(cmd);

    char response[256];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"updated\",\"key\":\"%s\"}", key);
    send(client_sock, response, strlen(response), 0);
}

/* Handle config read from HTTP */
void handle_config_read(int client_sock, const char *path) {
    /* VULN: Path traversal in config file reading */
    const char *config_file = path + 12;  /* skip "/api/config/" */
    char filepath[256];
    sprintf(filepath, "/etc/smarthome/%s", config_file);

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"Config not found\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    char content[4096];
    int bytes = fread(content, 1, sizeof(content) - 1, fp);
    content[bytes] = '\0';
    fclose(fp);

    char response[4096 + 128];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n%s", content);
    send(client_sock, response, strlen(response), 0);
}

/* Safe config read */
void handle_config_read_safe(int client_sock, const char *path) {
    const char *config_file = path + 12;
    char *safe_name = sanitize_filename(config_file);
    if (!safe_name) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"Invalid path\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/etc/smarthome/%s", safe_name);
    free(safe_name);

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"Config not found\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    char content[4096];
    int bytes = fread(content, 1, sizeof(content) - 1, fp);
    content[bytes] = '\0';
    fclose(fp);

    char response[4096 + 128];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n\r\n%s", content);
    send(client_sock, response, strlen(response), 0);
}

/* Export config in specified format */
void export_config(const char *format, const char *output_path) {
    /* VULN: Command injection */
    char cmd[512];
    sprintf(cmd, "config-export --format %s --output %s", format, output_path);
    system(cmd);
}

/* Config validation */
int validate_config_key(const char *key) {
    for (int i = 0; key[i]; i++) {
        char c = key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.')) {
            return 0;
        }
    }
    return 1;
}
