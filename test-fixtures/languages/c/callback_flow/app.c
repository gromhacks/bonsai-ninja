#include <stdlib.h>

void executor(const char *cmd) {
    system(cmd);
}

void run_cb(void (*cb)(const char *), const char *value) {
    cb(value);
}

void pass_to_callback(void) {
    const char *t = getenv("CMD");
    run_cb(executor, t);
}
