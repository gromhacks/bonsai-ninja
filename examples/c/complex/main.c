#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"

/* Forward declarations */
void handle_device_command(int client_sock, const char *request);
void handle_firmware_upload(int client_sock, const char *request);
void handle_config_update(int client_sock, const char *request);
void handle_config_read(int client_sock, const char *path);

#define MAX_BUFFER 4096
#define MAX_HEADER 1024
#define HTTP_PORT 8080

struct http_request {
    char method[16];
    char path[256];
    char body[MAX_BUFFER];
    int body_length;
    char headers[MAX_HEADER];
};

struct route_entry {
    const char *path;
    void (*handler)(int, const char *);
};

/* Parse HTTP request from raw buffer */
int parse_http_request(const char *raw, struct http_request *req) {
    memset(req, 0, sizeof(struct http_request));
    sscanf(raw, "%15s %255s", req->method, req->path);

    const char *body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(req->body, body_start, MAX_BUFFER - 1);
        req->body_length = strlen(req->body);
    }
    return 0;
}

/* Dispatch request to handler */
void dispatch_route(int client_sock, struct http_request *req) {
    if (strncmp(req->path, "/api/device/", 12) == 0) {
        handle_device_command(client_sock, req->body);
    } else if (strncmp(req->path, "/api/firmware", 13) == 0) {
        handle_firmware_upload(client_sock, req->body);
    } else if (strncmp(req->path, "/api/config", 11) == 0) {
        if (strcmp(req->method, "GET") == 0) {
            handle_config_read(client_sock, req->path);
        } else {
            handle_config_update(client_sock, req->body);
        }
    } else {
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\nNot Found";
        send(client_sock, resp, strlen(resp), 0);
    }
}

/* VULN: Command injection via device control */
void execute_device_action(const char *device_id, const char *action) {
    char cmd[512];
    /* VULN: User input concatenated into command */
    sprintf(cmd, "device-ctl --id %s --action %s", device_id, action);
    system(cmd);
}

/* Safe version: uses allowlist */
void execute_device_action_safe(const char *device_id, const char *action) {
    const char *allowed_actions[] = {"on", "off", "status", "reset", NULL};
    int valid = 0;
    for (int i = 0; allowed_actions[i]; i++) {
        if (strcmp(action, allowed_actions[i]) == 0) {
            valid = 1;
            break;
        }
    }
    if (!valid) return;
    char *argv[] = {"device-ctl", "--id", (char *)device_id, "--action", (char *)action, NULL};
    execvp("device-ctl", argv);
}

/* VULN: Buffer overflow in header parsing - Deep Chain 1 */
void process_client(int client_sock) {
    char buf[MAX_BUFFER];
    int bytes = recv(client_sock, buf, MAX_BUFFER - 1, 0);
    if (bytes <= 0) return;
    buf[bytes] = '\0';

    struct http_request req;
    parse_http_request(buf, &req);
    dispatch_route(client_sock, &req);
    close(client_sock);
}

/* VULN: Format string vulnerability */
void log_request(const char *client_ip, const char *request_line) {
    /* VULN: user input as format string */
    printf(request_line);
    printf("\n");
}

/* Safe version */
void log_request_safe(const char *client_ip, const char *request_line) {
    printf("%s: %s\n", client_ip, request_line);
}

/* VULN: Integer overflow in allocation */
void *allocate_buffer(unsigned int count, unsigned int size) {
    /* VULN: multiplication can overflow */
    unsigned int total = count * size;
    return malloc(total);
}

/* Safe version */
void *allocate_buffer_safe(unsigned int count, unsigned int size) {
    if (count > 0 && size > (unsigned int)(-1) / count) {
        return NULL;  /* overflow */
    }
    return malloc(count * size);
}

/* VULN: SQL injection via SQLite */
void query_device_log(const char *device_id) {
    char sql[512];
    sprintf(sql, "SELECT * FROM device_logs WHERE device_id = '%s'", device_id);
    /* sqlite3_exec(db, sql, callback, 0, &err_msg); */
    printf("Query: %s\n", sql);
}

/* Safe version with parameterized query */
void query_device_log_safe(const char *device_id) {
    const char *sql = "SELECT * FROM device_logs WHERE device_id = ?";
    /* sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
       sqlite3_bind_text(stmt, 1, device_id, -1, SQLITE_TRANSIENT); */
    printf("Safe query with param: %s\n", sql);
}

/* VULN: Path traversal */
int read_log_file(const char *filename, char *output, int output_size) {
    char path[256];
    sprintf(path, "/var/log/smarthome/%s", filename);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int bytes = fread(output, 1, output_size - 1, fp);
    output[bytes] = '\0';
    fclose(fp);
    return bytes;
}

/* Safe version */
int read_log_file_safe(const char *filename, char *output, int output_size) {
    char *safe_name = sanitize_filename(filename);
    if (!safe_name) return -1;
    char path[256];
    snprintf(path, sizeof(path), "/var/log/smarthome/%s", safe_name);
    FILE *fp = fopen(path, "r");
    free(safe_name);
    if (!fp) return -1;
    int bytes = fread(output, 1, output_size - 1, fp);
    output[bytes] = '\0';
    fclose(fp);
    return bytes;
}

/* VULN: Null dereference potential */
void process_sensor_data(const char *json_data) {
    char *value = strstr(json_data, "\"temperature\":");
    /* value could be NULL */
    double temp = atof(value + 14);
    printf("Temperature: %.1f\n", temp);
}

int main(int argc, char *argv[]) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(HTTP_PORT);

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    listen(server_sock, 10);
    printf("Smart Home Hub listening on port %d\n", HTTP_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) continue;
        process_client(client_sock);
    }

    close(server_sock);
    return 0;
}
