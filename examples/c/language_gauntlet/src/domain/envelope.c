#include <string.h>

#include "gauntlet/envelope.h"

EnvelopeAlias envelope_from_cli(const char *raw, const char *user) {
    EnvelopeAlias env = {KIND_RUN, {0}, {0}, 0, NULL};
    strncpy(env.cmd, raw, sizeof(env.cmd) - 1);
    strncpy(env.user, user, sizeof(env.user) - 1);
    env.length = (int)strlen(env.cmd);
    return env;
}

const char *envelope_cmd(const EnvelopeAlias *env) {
    return env->selected != NULL ? env->selected : env->cmd;
}
