#include <stdlib.h>

#include "gauntlet/executor.h"

int execute(const char *cmd) {
    /* SINK -- system() / CWE-78. */
    return system(cmd);
}

int clean_twin(void) {
    /* NEGATIVE -- the constant argument must remain untainted. */
    return system("echo clean");
}
