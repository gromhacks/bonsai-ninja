#include <cstdlib>

extern "C" void execute(const char *cmd) {
    // POSITIVE (terminal cross-file sink)
    std::system(cmd);
}
