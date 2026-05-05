/* Mega-flow C fixture — argv is the SOURCE (tainted CLI input),
 * threaded through every idiomatic C flow construct (structs,
 * function pointers, switch/goto, for/while/do-while loops, and
 * pointer/buffer bookkeeping). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "envelope.h"

extern int orchestrate(struct Envelope *env);

int main(int argc, char *argv[]) {
    /* SOURCE — argv CLI input. */
    const char *raw = argc > 1 ? argv[1] : "";
    const char *user = argc > 2 ? argv[2] : "anon";

    struct Envelope env;
    env.kind = KIND_RUN;
    strncpy(env.cmd, raw, sizeof(env.cmd) - 1);
    env.cmd[sizeof(env.cmd) - 1] = '\0';
    strncpy(env.user, user, sizeof(env.user) - 1);
    env.user[sizeof(env.user) - 1] = '\0';
    env.length = (int)strlen(env.cmd);

    return orchestrate(&env);
}
