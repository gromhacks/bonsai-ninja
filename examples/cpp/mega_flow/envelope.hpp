#ifndef MEGA_FLOW_ENVELOPE_HPP
#define MEGA_FLOW_ENVELOPE_HPP

#include <string>
#include <vector>

enum class Kind { Run, Eval };

// Envelope — aggregate value type carrying the tainted cmd.
struct Envelope {
    Kind kind;
    std::string cmd;
    std::string user;
    int length;
    std::vector<std::string> extras;
};

#endif
