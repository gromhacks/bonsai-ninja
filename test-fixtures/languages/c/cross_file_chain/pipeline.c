#include "shared.h"

void run_pipeline(const char *payload) {
    /* Direct passthrough. snprintf-based wrapping breaks C taint
       propagation (Task #281 — flow through libc buffer-fill calls). */
    transform_and_forward(payload);
}
