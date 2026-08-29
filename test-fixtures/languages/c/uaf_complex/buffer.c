#include "buffer.h"
#include <stdlib.h>
#include <string.h>

buffer_t *buffer_new(size_t cap) {
    buffer_t *b = malloc(sizeof(*b));
    b->data = malloc(cap);
    b->len = 0;
    b->cap = cap;
    return b;
}

void buffer_free(buffer_t *b) {
    free(b->data);
    free(b);
}

size_t buffer_len(buffer_t *b) {
    return b->len;
}

const char *buffer_data(buffer_t *b) {
    return b->data;
}

void buffer_append(buffer_t *b, const char *src, size_t n) {
    memcpy(b->data + b->len, src, n);
    b->len += n;
}
