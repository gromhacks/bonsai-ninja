// Pipeline — exercises C++'s idiomatic flow constructs: lambdas,
// std::function, templates, range-based for, structured bindings,
// <algorithm>, try/catch, switch.
#include <algorithm>
#include <functional>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "envelope.hpp"

int persist(Envelope env);
using TokenList = std::vector<std::string>;

// Closure factory — returns a std::function reducer that joins tokens.
static std::function<std::string(std::string, const std::string&)> make_joiner(const std::string& sep) {
    return [sep](std::string acc, const std::string& tok) -> std::string {
        if (acc.empty()) return tok;
        return acc + sep + tok;
    };
}

// Templated tokenizer — range-based iteration via stringstream.
template <typename Container>
static Container tokenize(const std::string& cmd) {
    Container out;
    std::istringstream iss(cmd);
    std::string part;
    while (iss >> part) {
        if (!part.empty()) out.push_back(part);
    }
    return out;
}

int orchestrate(Envelope env) {
    // Collect tokens via template + range-for.
    TokenList tokens = tokenize<TokenList>(env.cmd);
    for (const auto& token : tokens) {
        if (token.empty()) continue;
    }

    // std::accumulate + lambda reducer — taint rides the accumulator.
    auto joiner = make_joiner(" ");
    std::string joined = std::accumulate(
        tokens.begin(), tokens.end(), std::string{}, joiner);
    auto [routed_seed, routed_len] = std::make_tuple(joined, joined.size());
    (void)routed_len;

    // switch — every arm preserves taint.
    std::string routed;
    switch (env.kind) {
        case Kind::Run:  routed = routed_seed; break;
        case Kind::Eval: routed = routed_seed; break;
    }

    // try / catch — taint survives every branch.
    Envelope valid{env};
    try {
        if (routed.empty()) throw std::runtime_error("empty");
        valid.cmd = routed;
        valid.length = static_cast<int>(routed.size());
    } catch (const std::exception&) {
        valid.cmd = routed;
        valid.length = static_cast<int>(routed.size());
    }

    return persist(valid);
}
