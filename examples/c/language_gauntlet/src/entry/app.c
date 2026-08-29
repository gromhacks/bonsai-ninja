/* Compiler gauntlet: a socket buffer enters a factory-built struct, crosses nested
 * translation units, callbacks, branches, loops, stored fields, and a sink. */
#include "gauntlet/envelope.h"
#include "gauntlet/pipeline.h"
#include <sys/socket.h>
#include <sys/types.h>

static int handle_request(int client_fd) {
    char raw[256] = {0};
    /* SOURCE -- recv writes attacker-controlled network bytes to raw. */
    ssize_t received = recv(client_fd, raw, sizeof(raw) - 1, 0);
    if (received <= 0) {
        return 0;
    }
    raw[received] = '\0';
    const char *user = "remote";
    EnvelopeAlias env = envelope_from_cli(raw, user);
    return orchestrate(&env, raw);
}

int main(void) {
    return handle_request(0);
}
