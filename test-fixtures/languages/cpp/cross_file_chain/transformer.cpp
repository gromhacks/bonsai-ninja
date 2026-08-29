extern "C" void execute(const char *cmd);

extern "C" void transform_and_forward(const char *value) {
    /* Direct passthrough — std::transform would break C++ taint
       propagation through std::string state (Task #281). */
    execute(value);
}
