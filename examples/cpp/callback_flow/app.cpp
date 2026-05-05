#include <cstdlib>

void executor(const char *cmd) {
    std::system(cmd);
}

void run_cb(void (*cb)(const char *), const char *value) {
    cb(value);
}

void pass_to_callback() {
    const char *t = std::getenv("CMD");
    if (t) run_cb(executor, t);
}
