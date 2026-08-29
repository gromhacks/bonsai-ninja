#include <cstdlib>

#include "gauntlet/runtime/executor.hpp"

namespace gauntlet {

int execute(const std::string& cmd) {
    // SINK -- std::system / CWE-78.
    return std::system(cmd.c_str());
}

int clean_twin() {
    // NEGATIVE -- the constant argument must remain untainted.
    return std::system("echo clean");
}

}  // namespace gauntlet
