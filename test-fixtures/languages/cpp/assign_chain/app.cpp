// Assignment-chain audit fixture (C++).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>

extern "C" void run_in_other_file(const char *cmd);

static const char *CONST_OK = "ls /tmp";

static std::string passthrough(const std::string &x) { return x; }
static std::string wrap(const std::string &x) { return std::string("wrapped:") + x; }
static std::string combine(const std::string &acc, const std::string &item) {
    return acc + ":" + item;
}

struct Bag {
    std::string payload;
};

void chain_simple() {
    // POSITIVE
    const char *tmp = std::getenv("CMD1");
    if (tmp) std::system(tmp);
}

void chain_multi_hop() {
    // POSITIVE
    const char *t1 = std::getenv("CMD2");
    if (!t1) return;
    std::string t2 = passthrough(t1);
    std::string t3 = wrap(t2);
    std::string t4 = passthrough(t3);
    std::system(t4.c_str());
}

void chain_branch_join(int cond) {
    // POSITIVE on tainted leg
    std::string t;
    if (cond) {
        const char *e = std::getenv("CMD3");
        t = e ? e : "";
    } else {
        t = "safe-static";
    }
    std::system(t.c_str());
}

void chain_loop_carried(const std::vector<std::string> &items) {
    // POSITIVE
    const char *e = std::getenv("CMD4");
    std::string acc = e ? e : "";
    for (const auto &item : items) {
        acc = combine(acc, item);
    }
    std::system(acc.c_str());
}

void chain_field_write() {
    // POSITIVE
    Bag bag;
    const char *e = std::getenv("CMD5");
    bag.payload = e ? e : "";
    std::system(bag.payload.c_str());
}

void chain_subscript_write() {
    // POSITIVE
    std::map<std::string, std::string> cmds;
    const char *e = std::getenv("CMD6");
    cmds["x"] = e ? e : "";
    std::system(cmds["x"].c_str());
}

void chain_clean_constant() {
    // NEGATIVE
    (void)std::getenv("IGNORED");
    std::system(CONST_OK);
}

void chain_cross_file() {
    // POSITIVE
    const char *t = std::getenv("CMD9");
    if (t) run_in_other_file(t);
}
