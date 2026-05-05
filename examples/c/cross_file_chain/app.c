/* Cross-file argument flow audit fixture (C). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"

void handler(void) {
    /* POSITIVE */
    const char *user = getenv("CMD");
    run_pipeline(user);
}

void handler_split(void) {
    /* POSITIVE */
    const char *user = getenv("FROM");
    const char *flag = getenv("FLAG");
    char joined[512];
    snprintf(joined, sizeof(joined), "%s:%s", user ? user : "", flag ? flag : "");
    run_pipeline(joined);
}
