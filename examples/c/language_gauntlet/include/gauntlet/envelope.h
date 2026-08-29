#ifndef LANGUAGE_GAUNTLET_ENVELOPE_H
#define LANGUAGE_GAUNTLET_ENVELOPE_H

#include <stddef.h>

enum Kind { KIND_RUN, KIND_EVAL };

struct Envelope {
    enum Kind kind;
    char cmd[512];
    char user[64];
    int length;
    const char *selected;
};

typedef struct Envelope EnvelopeAlias;

EnvelopeAlias envelope_from_cli(const char *raw, const char *user);
const char *envelope_cmd(const EnvelopeAlias *env);

#endif
