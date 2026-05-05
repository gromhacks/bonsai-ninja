// Cross-file argument flow audit fixture (C++).
#include <cstdio>
#include <cstdlib>
#include <string>

extern "C" void run_pipeline(const char *payload);

void handler() {
    // POSITIVE
    const char *user = std::getenv("CMD");
    if (user) run_pipeline(user);
}

void handler_split() {
    // POSITIVE
    const char *user = std::getenv("FROM");
    const char *flag = std::getenv("FLAG");
    std::string joined = std::string(user ? user : "") + ":" + (flag ? flag : "");
    run_pipeline(joined.c_str());
}
