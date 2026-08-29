#include <cstdlib>
#include <cctype>
#include <string>

void unsanitized() {
    const char *t = std::getenv("CMD");
    if (t) std::system(t);
}

void sanitized() {
    const char *t = std::getenv("CMD");
    if (!t) return;
    std::string safe;
    for (size_t i = 0; t[i]; i++) {
        if (std::isalnum(static_cast<unsigned char>(t[i]))) safe.push_back(t[i]);
    }
    std::system(safe.c_str());
}
