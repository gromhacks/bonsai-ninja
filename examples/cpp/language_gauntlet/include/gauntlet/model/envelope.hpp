#ifndef LANGUAGE_GAUNTLET_ENVELOPE_HPP
#define LANGUAGE_GAUNTLET_ENVELOPE_HPP

#include <string>
#include <vector>

namespace gauntlet {

enum class Kind { Run, Eval };

struct Envelope {
    Kind kind;
    std::string cmd;
    std::string user;
    int length;
    std::vector<std::string> extras;

    static Envelope from_cli(std::string raw, std::string user);
};

using Payload = Envelope;

}  // namespace gauntlet

#endif
