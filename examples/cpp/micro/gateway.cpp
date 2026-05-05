#include "gateway.h"
#include "user_service.h"
#include <iostream>

namespace micro {

std::string handle_request(const std::map<std::string, std::string>& params) {
    std::string token = params.at("token");    // source: user input
    std::string action = params.at("action");  // source: user input

    UserInfo user = get_user(token);           // flows to SQL injection
    std::string result = update_user(token, action); // flows to command injection

    return "{\"user\": \"" + user.id + "\", \"result\": \"" + result + "\"}";
}

}
