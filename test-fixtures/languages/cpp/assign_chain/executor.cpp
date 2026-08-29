#include <cstdlib>

extern "C" void run_in_other_file(const char *cmd) {
    // POSITIVE (cross-file)
    std::system(cmd);
}
