#include <cstdlib>

void taint_one_leg(int cond) {
    const char *x;
    if (cond) { x = std::getenv("CMD"); if (!x) x = ""; }
    else { x = "safe-static"; }
    std::system(x);
}

void taint_overwritten(int cond) {
    const char *x = std::getenv("CMD");
    if (cond) { x = "clean-then"; }
    else { x = "clean-else"; }
    std::system(x);
}
