#include <cstdlib>

void tainted_through_try() {
    const char *t = nullptr;
    try {
        t = std::getenv("CMD");
    } catch (...) {
        t = "";
    }
    if (t) std::system(t);
}
