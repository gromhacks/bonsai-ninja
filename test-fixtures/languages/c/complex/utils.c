#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "utils.h"

/* Extract a field from simple JSON */
void extract_json_field(const char *json, const char *field, char *output, int output_size) {
    output[0] = '\0';
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", field);

    const char *start = strstr(json, search);
    if (!start) return;
    start += strlen(search);

    const char *end = strchr(start, '"');
    if (!end) return;

    int len = end - start;
    if (len >= output_size) len = output_size - 1;
    strncpy(output, start, len);
    output[len] = '\0';
}

/* Validate identifier (alphanumeric + underscore) */
int is_valid_identifier(const char *str) {
    if (!str || !str[0]) return 0;
    for (int i = 0; str[i]; i++) {
        char c = str[i];
        if (!isalnum(c) && c != '_' && c != '-') return 0;
    }
    return 1;
}

/* Validate IP address format */
int is_valid_ip(const char *ip) {
    int parts[4];
    int count = sscanf(ip, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    if (count != 4) return 0;
    for (int i = 0; i < 4; i++) {
        if (parts[i] < 0 || parts[i] > 255) return 0;
    }
    return 1;
}

/* Sanitize filename - remove path components */
char *sanitize_filename(const char *filename) {
    if (!filename) return NULL;

    /* Find last path separator */
    const char *base = filename;
    const char *p = filename;
    while (*p) {
        if (*p == '/' || *p == '\\') base = p + 1;
        p++;
    }

    /* Check for directory traversal */
    if (strstr(base, "..") != NULL) return NULL;

    /* Validate characters */
    for (p = base; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '-') return NULL;
    }

    char *result = (char *)malloc(strlen(base) + 1);
    if (result) strcpy(result, base);
    return result;
}

/* Duplicate a string */
char *string_duplicate(const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    char *dup = (char *)malloc(len + 1);
    if (dup) memcpy(dup, str, len + 1);
    return dup;
}

/* Check if string starts with prefix */
int string_starts_with(const char *str, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    return strncmp(str, prefix, prefix_len) == 0;
}

/* Trim whitespace from string */
void string_trim(char *str) {
    if (!str) return;
    /* Trim leading */
    char *start = str;
    while (isspace(*start)) start++;
    if (start != str) memmove(str, start, strlen(start) + 1);
    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        *end = '\0';
        end--;
    }
}

/* Simple hash function */
unsigned int hash_string(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* Base64 encoding table */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, int length) {
    int output_len = 4 * ((length + 2) / 3);
    char *encoded = (char *)malloc(output_len + 1);
    if (!encoded) return NULL;

    int i, j;
    for (i = 0, j = 0; i < length;) {
        unsigned int octet_a = i < length ? data[i++] : 0;
        unsigned int octet_b = i < length ? data[i++] : 0;
        unsigned int octet_c = i < length ? data[i++] : 0;
        unsigned int triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        encoded[j++] = b64_table[(triple >> 18) & 0x3F];
        encoded[j++] = b64_table[(triple >> 12) & 0x3F];
        encoded[j++] = b64_table[(triple >> 6) & 0x3F];
        encoded[j++] = b64_table[triple & 0x3F];
    }
    encoded[j] = '\0';
    return encoded;
}
