#include <string>
#include <sys/socket.h>

#include "gauntlet/model/envelope.hpp"
#include "gauntlet/pipeline/pipeline.hpp"

static int handle_request(int client_fd) {
    char buffer[256] = {0};
    // SOURCE -- recv writes attacker-controlled network bytes to buffer.
    const auto received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return 0;
    }
    std::string raw = buffer;
    std::string user = "remote";
    gauntlet::Payload env = gauntlet::Envelope::from_cli(raw, user);
    return gauntlet::orchestrate(std::move(env), raw);
}

int main() {
    return handle_request(0);
}
