#ifndef MEGA_FLOW_ENVELOPE_H
#define MEGA_FLOW_ENVELOPE_H

/* Envelope — struct carrying the tainted cmd field. */
enum Kind { KIND_RUN, KIND_EVAL };

struct Envelope {
    enum Kind kind;
    char cmd[512];
    char user[64];
    int length;
};

#endif
