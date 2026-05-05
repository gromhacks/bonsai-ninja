extern "C" void transform_and_forward(const char *value);

extern "C" void run_pipeline(const char *payload) {
    /* Direct passthrough — std::string concat would break C++ taint
       propagation through string-builder paths (related: Task #281). */
    transform_and_forward(payload);
}
