#include <stdlib.h>
#include <string.h>

static const char *CONST_OK = "ls /tmp";

void decoy(void) {
    const char *unused = getenv("IGNORED");
    (void)unused;
    system(CONST_OK);
}

size_t unrelated_chain(void) {
    const char *a = "hello";
    return strlen(a);
}
