#include "shared.h"

void transform_and_forward(const char *value) {
    /* Direct passthrough; snprintf-/strncpy-based transforms break
       C taint propagation through stack-buffer fills (Task #281). */
    execute(value);
}
