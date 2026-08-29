#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "gauntlet/envelope.h"
#include "gauntlet/pipeline.h"
#include "gauntlet/storage.h"

typedef void (*joiner_fn)(char *dst, size_t cap, const char *sep, const char *tok);

static void joiner_impl(char *dst, size_t cap, const char *sep, const char *tok) {
    if (dst[0] == '\0') {
        strncpy(dst, tok, cap - 1);
        dst[cap - 1] = '\0';
        return;
    }
    strncat(dst, sep, cap - strlen(dst) - 1);
    strncat(dst, tok, cap - strlen(dst) - 1);
}

static void collect_tokens(const char *cmd, char *joined, size_t cap, joiner_fn joiner) {
    char buffer[512] = {0};
    strncpy(buffer, cmd, sizeof(buffer) - 1);
    char *tok = strtok(buffer, " ");
    while (tok != NULL) {
        if (tok[0] == '\0') {
            break;
        }
        joiner(joined, cap, " ", tok);
        tok = strtok(NULL, " ");
    }
}

static const char *route_command(const EnvelopeAlias *env, const char *joined) {
    switch (env->kind) {
        case KIND_RUN:
            return joined;
        case KIND_EVAL:
            return joined;
        default:
            goto fallback;
    }
fallback:
    return joined;
}

int orchestrate(EnvelopeAlias *env, const char *source) {
    char joined[512] = {0};
    joiner_fn joiner = joiner_impl;
    collect_tokens(env->cmd, joined, sizeof(joined), joiner);

    const char *selected = route_command(env, source);
    char routed[512] = {0};
    strncpy(routed, selected, sizeof(routed) - 1);

    size_t pass = 0;
    do {
        pass++;
    } while (pass < 1 && routed[0] != '\0');

    for (size_t i = strlen(routed); i > 0 && isspace((unsigned char)routed[i - 1]); --i) {
        if (routed[i - 1] == '\t') {
            continue;
        }
        routed[i - 1] = '\0';
    }

    strncpy(env->cmd, routed, sizeof(env->cmd) - 1);
    env->cmd[sizeof(env->cmd) - 1] = '\0';
    env->length = (int)strlen(env->cmd);
    env->selected = selected;
    return persist(env, selected);
}
