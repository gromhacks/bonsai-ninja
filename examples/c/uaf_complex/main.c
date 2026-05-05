#include "buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Linear UAF: free then read.
static void linear_uaf(void) {
    buffer_t *p = buffer_new(64);
    buffer_append(p, "hello", 5);
    buffer_free(p);
    printf("%s", buffer_data(p));
}

// Conditional UAF: free on the error path.
static int conditional_uaf(int err) {
    buffer_t *p = buffer_new(64);
    if (err) {
        buffer_free(p);
    }
    return (int)buffer_len(p);
}

// Double-free on the same binding.
static void double_free(void) {
    int *p = malloc(64);
    free(p);
    free(p);
}

// Loop UAF: free on the first iteration leaves the rest dangling.
static void loop_uaf(int n) {
    buffer_t *p = buffer_new(64);
    for (int i = 0; i < n; i++) {
        if (i == 0) {
            buffer_free(p);
        }
        buffer_append(p, "x", 1);
    }
}

// Lock-after-unlock.
static void lock_misuse(pthread_mutex_t *m) {
    pthread_mutex_unlock(m);
    pthread_mutex_lock(m);
}

int main(void) {
    linear_uaf();
    (void)conditional_uaf(1);
    double_free();
    loop_uaf(4);
    return 0;
}
