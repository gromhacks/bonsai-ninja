#include <stdlib.h>

void run_in_other_file(const char *cmd) {
    /* POSITIVE (cross-file) */
    system(cmd);
}
