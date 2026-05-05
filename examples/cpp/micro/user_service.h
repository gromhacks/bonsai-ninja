#ifndef USER_SERVICE_H
#define USER_SERVICE_H

#include <string>

namespace micro {

struct UserInfo {
    std::string id;
    std::string token;
};

UserInfo get_user(const std::string& token);
std::string update_user(const std::string& token, const std::string& action);

}

#endif
