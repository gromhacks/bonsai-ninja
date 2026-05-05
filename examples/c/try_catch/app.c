// C has no try/catch. Use setjmp/longjmp pattern as a "try" analog.
// More commonly: skip the try-body — taint must flow normally.
#include <stdlib.h>

void tainted_through_try(void) {
    const char *t = getenv("CMD");
    system(t);
}
