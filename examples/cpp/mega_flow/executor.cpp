#include <cstdlib>
#include <string>

int execute(const std::string& cmd) {
    // SINK — std::system · cpp.cmdi.system · CWE-78
    return std::system(cmd.c_str());
}

int clean_twin() {
    // NEGATIVE — same sink kind with a constant argument must not report.
    return std::system("echo clean");
}
