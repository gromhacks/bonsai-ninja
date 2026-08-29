#ifndef UTILS_H
#define UTILS_H

/* Input extraction */
void extract_json_field(const char *json, const char *field, char *output, int output_size);

/* Input validation */
int is_valid_identifier(const char *str);
int is_valid_ip(const char *ip);
char *sanitize_filename(const char *filename);

/* String utilities */
char *string_duplicate(const char *str);
int string_starts_with(const char *str, const char *prefix);
void string_trim(char *str);

/* Encoding */
char *base64_encode(const unsigned char *data, int length);
unsigned char *base64_decode(const char *encoded, int *out_length);

/* Hashing */
unsigned int hash_string(const char *str);

#endif /* UTILS_H */
