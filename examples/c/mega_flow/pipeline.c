/* Pipeline — exercises C's idiomatic flow constructs: structs,
 * function pointers, switch with fall-through, for / while / do-while
 * loops, goto, pointer arithmetic, typedef. */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "envelope.h"

extern int persist(struct Envelope *env);

/* Function-pointer typedef — joins tokens via `sep`. */
typedef void (*joiner_fn)(char *dst, size_t cap, const char *sep, const char *tok);

/* Concrete joiner — behaves like a closure when we pass `sep` upstream. */
static void joiner_impl(char *dst, size_t cap, const char *sep, const char *tok) {
    if (dst[0] == '\0') {
        strncpy(dst, tok, cap - 1);
        dst[cap - 1] = '\0';
    } else {
        strncat(dst, sep, cap - strlen(dst) - 1);
        strncat(dst, tok, cap - strlen(dst) - 1);
    }
}

int orchestrate(struct Envelope *env) {
    /* Make a mutable copy to strtok. */
    char buffer[512];
    strncpy(buffer, env->cmd, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    /* while-loop + strtok — tokenise and reduce via function pointer. */
    char joined[512] = {0};
    joiner_fn joiner = joiner_impl;
    char *tok = strtok(buffer, " ");
    while (tok != NULL) {
        if (tok[0] != '\0') {
            joiner(joined, sizeof(joined), " ", tok);
        }
        tok = strtok(NULL, " ");
    }

    /* switch — every arm preserves taint. */
    char routed[512] = {0};
    size_t pass = 0;
    switch (env->kind) {
        case KIND_RUN:
            strncpy(routed, joined, sizeof(routed) - 1);
            routed[sizeof(routed) - 1] = '\0';
            break;
        case KIND_EVAL:
            strncpy(routed, joined, sizeof(routed) - 1);
            routed[sizeof(routed) - 1] = '\0';
            break;
        default:
            goto fallback;
    }
    goto persist_step;

fallback:
    strncpy(routed, joined, sizeof(routed) - 1);
    routed[sizeof(routed) - 1] = '\0';

persist_step:
    /* do-while — normalize through at least one pass, preserving taint. */
    do {
        pass++;
    } while (pass < 1 && routed[0] != '\0');

    /* for-loop — trim trailing whitespace. */
    for (size_t i = strlen(routed); i > 0 && isspace((unsigned char)routed[i - 1]); --i) {
        if (routed[i - 1] == '\t') {
            continue;
        }
        routed[i - 1] = '\0';
    }

    strncpy(env->cmd, routed, sizeof(env->cmd) - 1);
    env->cmd[sizeof(env->cmd) - 1] = '\0';
    env->length = (int)strlen(env->cmd);

    return persist(env);
}
