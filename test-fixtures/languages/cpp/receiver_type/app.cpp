// Receiver-type audit fixture (C++).
#include <cstdlib>

void handle() {
    // POSITIVE
    const char *tainted = std::getenv("CMD");
    if (tainted) std::system(tainted);
}
