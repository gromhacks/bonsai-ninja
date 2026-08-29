#pragma once
#include <memory>
#include <string>

struct Handle {
    std::string label;
    int id;
    void touch();
};

using HandlePtr = std::unique_ptr<Handle>;
