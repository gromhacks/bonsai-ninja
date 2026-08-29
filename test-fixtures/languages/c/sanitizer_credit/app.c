#include <stdlib.h>
#include <ctype.h>
#include <string.h>

void unsanitized(void) {
    const char *t = getenv("CMD");
    system(t);
}

void sanitized(void) {
    const char *t = getenv("CMD");
    if (!t) return;
    char safe[256] = {0};
    size_t j = 0;
    for (size_t i = 0; t[i] && j + 1 < sizeof(safe); i++) {
        if (isalnum((unsigned char)t[i])) safe[j++] = t[i];
    }
    safe[j] = 0;
    system(safe);
}
