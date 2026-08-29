#include "handle.h"
#include <iostream>
#include <utility>

void Handle::touch() {
    id++;
}

// Use after `release()` — pointer abandoned but receiver still queried.
void use_after_release(HandlePtr ptr) {
    ptr.release();
    ptr.read();
}

// Double-release of the same unique_ptr.
void double_release(HandlePtr ptr) {
    ptr.release();
    ptr.release();
}

// Use after `std::move`.
void use_after_move(HandlePtr ptr) {
    auto moved = std::move(ptr);
    ptr.read();
}

// Aliased reset — first reset frees, second touches via the original.
void reset_then_use(HandlePtr ptr) {
    ptr.reset();
    ptr.read();
}

int main() {
    auto h1 = std::make_unique<Handle>();
    use_after_release(std::move(h1));
    auto h2 = std::make_unique<Handle>();
    double_release(std::move(h2));
    auto h3 = std::make_unique<Handle>();
    use_after_move(std::move(h3));
    auto h4 = std::make_unique<Handle>();
    reset_then_use(std::move(h4));
    return 0;
}
