#include "user_service.h"
#include "auth_service.h"

namespace micro {

UserInfo get_user(const std::string& token) {
    std::string user_id = verify_token(token);
    return UserInfo{user_id, token};
}

std::string update_user(const std::string& token, const std::string& action) {
    std::string user_id = verify_token(token);
    if (!user_id.empty()) {
        run_admin_command(user_id, action);
    }
    return user_id;
}

}
