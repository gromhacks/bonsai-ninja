#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

#define FIRMWARE_MAGIC 0xFEED1234
#define MAX_FIRMWARE_SIZE (16 * 1024 * 1024)

struct firmware_image {
    unsigned int magic;
    unsigned int version;
    unsigned int data_size;
    unsigned int checksum;
    char description[128];
    unsigned char *data;
};

/* Calculate simple checksum */
unsigned int calculate_checksum(const unsigned char *data, unsigned int size) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < size; i++) {
        sum += data[i];
    }
    return sum;
}

/* VULN: Integer overflow in firmware validation */
int validate_firmware_image(const unsigned char *raw_data, unsigned int raw_size) {
    if (raw_size < sizeof(struct firmware_image)) {
        return -1;
    }

    struct firmware_image *img = (struct firmware_image *)raw_data;
    if (img->magic != FIRMWARE_MAGIC) {
        return -1;
    }

    /* VULN: Integer overflow - data_size + sizeof(header) can wrap */
    unsigned int expected_size = img->data_size + sizeof(struct firmware_image);
    if (expected_size < img->data_size) {
        return -1;  /* overflow detected */
    }

    return 0;
}

/* Extract firmware from uploaded data */
struct firmware_image *extract_firmware(const unsigned char *data, unsigned int size) {
    struct firmware_image *img = (struct firmware_image *)malloc(sizeof(struct firmware_image));
    if (!img) return NULL;

    memcpy(img, data, sizeof(struct firmware_image));

    if (img->data_size > 0 && img->data_size < MAX_FIRMWARE_SIZE) {
        img->data = (unsigned char *)malloc(img->data_size);
        if (img->data) {
            memcpy(img->data, data + sizeof(struct firmware_image), img->data_size);
        }
    } else {
        img->data = NULL;
    }
    return img;
}

/* Apply firmware update */
int apply_firmware_update(struct firmware_image *img) {
    if (!img || !img->data) return -1;

    /* VULN: Command injection via description field */
    char cmd[512];
    sprintf(cmd, "firmware-apply --desc '%s' --version %u", img->description, img->version);
    system(cmd);

    return 0;
}

/* Safe version */
int apply_firmware_update_safe(struct firmware_image *img) {
    if (!img || !img->data) return -1;

    char version_str[32];
    snprintf(version_str, sizeof(version_str), "%u", img->version);

    char *argv[] = {"firmware-apply", "--version", version_str, NULL};
    /* execvp(argv[0], argv); */
    printf("Safe firmware apply: version=%s\n", version_str);
    return 0;
}

/* Free firmware image */
void free_firmware_image(struct firmware_image *img) {
    if (img) {
        if (img->data) free(img->data);
        free(img);
    }
}

/* VULN: Buffer overflow in version string building */
char *build_version_string(unsigned int major, unsigned int minor, unsigned int patch, const char *tag) {
    char *version = (char *)malloc(32);
    /* VULN: tag could be very long */
    sprintf(version, "%u.%u.%u-%s", major, minor, patch, tag);
    return version;
}

/* Safe version */
char *build_version_string_safe(unsigned int major, unsigned int minor, unsigned int patch, const char *tag) {
    char *version = (char *)malloc(128);
    snprintf(version, 128, "%u.%u.%u-%.64s", major, minor, patch, tag);
    return version;
}

/* Firmware rollback */
int rollback_firmware(const char *version) {
    char backup_path[256];
    snprintf(backup_path, sizeof(backup_path), "/var/firmware/backup/%s.bin", version);

    FILE *fp = fopen(backup_path, "rb");
    if (!fp) {
        printf("Backup not found: %s\n", backup_path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) {
        fclose(fp);
        return -1;
    }

    fread(data, 1, size, fp);
    fclose(fp);

    struct firmware_image *img = extract_firmware(data, size);
    if (img) {
        apply_firmware_update(img);
        free_firmware_image(img);
    }

    free(data);
    return 0;
}

/* Schedule firmware update */
int schedule_update(const char *cron_expr, const char *firmware_path) {
    /* VULN: Command injection */
    char cmd[512];
    sprintf(cmd, "crontab -l | { cat; echo \"%s /usr/sbin/firmware-update %s\"; } | crontab -",
            cron_expr, firmware_path);
    system(cmd);
    return 0;
}
