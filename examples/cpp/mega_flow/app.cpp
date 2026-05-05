// mega_flow C++ entry — argv is the SOURCE, threaded through every
// idiomatic C++ flow construct (lambdas, std::function, templates,
// smart pointers, structured bindings, range-for, exceptions,
// variants, inheritance + virtual, std::visit).
#include <string>
#include <vector>

#include "envelope.hpp"

int orchestrate(Envelope env);

int main(int argc, char *argv[]) {
    // SOURCE — argv tainted CLI input.
    std::string raw = argc > 1 ? argv[1] : "";
    std::string user = argc > 2 ? argv[2] : "anon";

    Envelope env{
        Kind::Run,
        std::string{raw},
        std::string{user},
        static_cast<int>(raw.size()),
        std::vector<std::string>{raw},
    };
    return orchestrate(env);
}
