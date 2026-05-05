#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "utils.h"

#define MAX_DEVICES 64
#define DEVICE_NAME_LEN 64
#define COMMAND_BUF_LEN 512

struct device {
    char id[32];
    char name[DEVICE_NAME_LEN];
    char type[32];
    int status;
    char firmware_version[16];
};

struct device_registry {
    struct device devices[MAX_DEVICES];
    int count;
};

static struct device_registry registry = { .count = 0 };

/* Register a new device */
int register_device(const char *id, const char *name, const char *type) {
    if (registry.count >= MAX_DEVICES) return -1;
    struct device *dev = &registry.devices[registry.count];
    strncpy(dev->id, id, sizeof(dev->id) - 1);
    strncpy(dev->name, name, sizeof(dev->name) - 1);
    strncpy(dev->type, type, sizeof(dev->type) - 1);
    dev->status = 0;
    strcpy(dev->firmware_version, "1.0.0");
    registry.count++;
    return 0;
}

/* Find device by ID */
struct device *find_device(const char *id) {
    for (int i = 0; i < registry.count; i++) {
        if (strcmp(registry.devices[i].id, id) == 0) {
            return &registry.devices[i];
        }
    }
    return NULL;
}

/* Handle device command from HTTP request */
void handle_device_command(int client_sock, const char *request) {
    char device_id[64];
    char action[64];
    char response[1024];

    /* Parse device_id and action from JSON body */
    extract_json_field(request, "device_id", device_id, sizeof(device_id));
    extract_json_field(request, "action", action, sizeof(action));

    struct device *dev = find_device(device_id);
    if (!dev) {
        snprintf(response, sizeof(response),
            "HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"Device not found\"}");
        send(client_sock, response, strlen(response), 0);
        return;
    }

    /* VULN: Command injection - action passed to system() */
    char cmd[COMMAND_BUF_LEN];
    sprintf(cmd, "/usr/local/bin/device-ctl %s %s", device_id, action);
    system(cmd);

    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"executed\",\"device\":\"%s\"}", device_id);
    send(client_sock, response, strlen(response), 0);
}

/* Safe version */
void handle_device_command_safe(int client_sock, const char *request) {
    char device_id[64];
    char action[64];

    extract_json_field(request, "device_id", device_id, sizeof(device_id));
    extract_json_field(request, "action", action, sizeof(action));

    if (!is_valid_identifier(device_id) || !is_valid_identifier(action)) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"Invalid input\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    char *argv[] = {"/usr/local/bin/device-ctl", device_id, action, NULL};
    /* execvp(argv[0], argv); */
    printf("Safe execution: %s %s %s\n", argv[0], argv[1], argv[2]);
}

/* VULN: Buffer overflow in firmware parsing - Deep Chain 1 */
struct firmware_header {
    char name[32];
    char version[16];
    unsigned int size;
    unsigned int checksum;
};

int parse_firmware_header(const char *data, struct firmware_header *header) {
    /* Extract firmware name - VULN: no bounds check */
    const char *name_field = strstr(data, "name:");
    if (name_field) {
        name_field += 5;
        /* VULN: strcpy with no bounds checking */
        char parsed_name[256];
        int i = 0;
        while (name_field[i] && name_field[i] != '\n' && i < 255) {
            parsed_name[i] = name_field[i];
            i++;
        }
        parsed_name[i] = '\0';
        strcpy(header->name, parsed_name);  /* SINK: buffer overflow */
    }

    const char *ver_field = strstr(data, "version:");
    if (ver_field) {
        ver_field += 8;
        strncpy(header->version, ver_field, sizeof(header->version) - 1);
    }

    return 0;
}

int validate_firmware_version(const char *version) {
    int major, minor, patch;
    if (sscanf(version, "%d.%d.%d", &major, &minor, &patch) != 3) {
        return -1;
    }
    if (major < 0 || minor < 0 || patch < 0) return -1;
    return 0;
}

/* Handle firmware upload */
void handle_firmware_upload(int client_sock, const char *request) {
    struct firmware_header header;
    memset(&header, 0, sizeof(header));

    parse_firmware_header(request, &header);

    if (validate_firmware_version(header.version) != 0) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"Invalid version\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    /* VULN: Integer overflow in size allocation */
    unsigned int total_size = header.size + 1024;
    char *firmware_buf = (char *)malloc(total_size);
    if (!firmware_buf) {
        const char *resp = "HTTP/1.1 500 Error\r\n\r\n{\"error\":\"Allocation failed\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    memcpy(firmware_buf, request, header.size);
    free(firmware_buf);

    char response[256];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"uploaded\",\"name\":\"%s\",\"version\":\"%s\"}",
        header.name, header.version);
    send(client_sock, response, strlen(response), 0);
}

/* VULN: Heap overflow via memcpy */
void update_device_firmware(struct device *dev, const char *new_version, const char *data, int data_len) {
    char *update_buf = (char *)malloc(256);
    /* VULN: data_len could exceed 256 */
    memcpy(update_buf, data, data_len);
    strncpy(dev->firmware_version, new_version, sizeof(dev->firmware_version) - 1);
    free(update_buf);
}

/* Get device status as JSON */
void get_device_status(int client_sock, const char *device_id) {
    struct device *dev = find_device(device_id);
    if (!dev) {
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"Not found\"}";
        send(client_sock, resp, strlen(resp), 0);
        return;
    }

    char response[512];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n\r\n{\"id\":\"%s\",\"name\":\"%s\",\"status\":%d,\"firmware\":\"%s\"}",
        dev->id, dev->name, dev->status, dev->firmware_version);
    send(client_sock, response, strlen(response), 0);
}

/* List all devices */
void list_devices(int client_sock) {
    char response[4096];
    int offset = 0;
    offset += snprintf(response + offset, sizeof(response) - offset,
        "HTTP/1.1 200 OK\r\n\r\n[");
    for (int i = 0; i < registry.count; i++) {
        if (i > 0) offset += snprintf(response + offset, sizeof(response) - offset, ",");
        offset += snprintf(response + offset, sizeof(response) - offset,
            "{\"id\":\"%s\",\"name\":\"%s\",\"type\":\"%s\"}",
            registry.devices[i].id, registry.devices[i].name, registry.devices[i].type);
    }
    offset += snprintf(response + offset, sizeof(response) - offset, "]");
    send(client_sock, response, offset, 0);
}
