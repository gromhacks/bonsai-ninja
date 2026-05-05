#include <stdlib.h>

int execute(const char *cmd) {
    /* SINK — system() · c.cmdi.system · CWE-78 */
    return system(cmd);
}

int clean_twin(void) {
    /* NEGATIVE — same sink kind with a constant argument must not report. */
    return system("echo clean");
}
