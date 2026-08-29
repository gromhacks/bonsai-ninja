#include <cstdlib>
#include <string>

static const char *CONST_OK = "ls /tmp";

void decoy() {
    const char *unused = std::getenv("IGNORED");
    (void)unused;
    std::system(CONST_OK);
}

std::string unrelated_chain() {
    std::string a = "hello";
    return a;
}
