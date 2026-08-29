/* Receiver-type audit fixture (C). C has no class system; this
   tests the simplest case where source/sink are libc free fns. */
#include <stdlib.h>

void handle(void) {
    /* POSITIVE */
    const char *tainted = getenv("CMD");
    system(tainted);
}
