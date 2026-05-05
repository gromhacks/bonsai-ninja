#include <stdlib.h>

void taint_one_leg(int cond) {
    const char *x;
    if (cond) { x = getenv("CMD"); }
    else { x = "safe-static"; }
    system(x);
}

void taint_overwritten(int cond) {
    const char *x = getenv("CMD");
    if (cond) { x = "clean-then"; }
    else { x = "clean-else"; }
    system(x);
}
