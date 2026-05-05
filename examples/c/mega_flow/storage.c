/* Storage — uses a static accessor helper to thread the tainted
 * cmd from the envelope to the executor. */
#include "envelope.h"

extern int execute(const char *cmd);

/* Accessor — extracts the tainted cmd from the envelope. */
static const char *envelope_cmd(const struct Envelope *env) {
    return env->cmd;
}

static int run(const struct Envelope *env) {
    const char *c = envelope_cmd(env);
    return execute(c);
}

int persist(struct Envelope *env) {
    return run(env);
}
