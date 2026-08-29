#include <utility>

#include "gauntlet/model/envelope.hpp"

namespace gauntlet {

Envelope Envelope::from_cli(std::string raw, std::string user) {
    auto length = static_cast<int>(raw.size());
    return Envelope{Kind::Run, raw, std::move(user), length, {std::move(raw)}};
}

}  // namespace gauntlet
