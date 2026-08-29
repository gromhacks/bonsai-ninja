/* Assignment-chain audit fixture (C). Uses getenv as the source per
   c.input.getenv rule, system as the cmdi sink. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void run_in_other_file(const char *cmd);

static const char *CONST_OK = "ls /tmp";

static const char *passthrough(const char *x) { return x; }
static char *wrap(const char *x) {
    static char buf[1024];
    snprintf(buf, sizeof(buf), "wrapped:%s", x);
    return buf;
}
static char *combine(const char *acc, const char *item) {
    static char buf[1024];
    snprintf(buf, sizeof(buf), "%s:%s", acc, item);
    return buf;
}

struct Bag {
    char payload[256];
};

void chain_simple(void) {
    /* POSITIVE: getenv -> system */
    const char *tmp = getenv("CMD1");
    system(tmp);
}

void chain_multi_hop(void) {
    /* POSITIVE: 4-hop chain */
    const char *t1 = getenv("CMD2");
    const char *t2 = passthrough(t1);
    const char *t3 = wrap(t2);
    const char *t4 = passthrough(t3);
    system(t4);
}

void chain_branch_join(int cond) {
    /* POSITIVE on tainted leg */
    const char *t;
    if (cond) {
        t = getenv("CMD3");
    } else {
        t = "safe-static";
    }
    system(t);
}

void chain_loop_carried(char **items, int n) {
    /* POSITIVE */
    const char *acc = getenv("CMD4");
    for (int i = 0; i < n; i++) {
        acc = combine(acc, items[i]);
    }
    system(acc);
}

void chain_field_write(void) {
    /* POSITIVE: struct field write */
    struct Bag bag;
    const char *src = getenv("CMD5");
    if (src) {
        strncpy(bag.payload, src, sizeof(bag.payload) - 1);
        bag.payload[sizeof(bag.payload) - 1] = '\0';
    }
    system(bag.payload);
}

void chain_clean_constant(void) {
    /* NEGATIVE: source unused; sink reads constant. */
    (void)getenv("IGNORED");
    system(CONST_OK);
}

void chain_cross_file(void) {
    /* POSITIVE: cross-file argument flow */
    const char *t = getenv("CMD9");
    run_in_other_file(t);
}
