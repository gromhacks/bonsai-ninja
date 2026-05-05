#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} buffer_t;

buffer_t *buffer_new(size_t cap);
void buffer_free(buffer_t *b);
size_t buffer_len(buffer_t *b);
const char *buffer_data(buffer_t *b);
void buffer_append(buffer_t *b, const char *src, size_t n);

#endif
