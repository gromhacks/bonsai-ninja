#ifndef AUTH_SERVICE_H
#define AUTH_SERVICE_H

#include <string>

namespace micro {

std::string verify_token(const std::string& token);
void run_admin_command(const std::string& user_id, const std::string& cmd);

}

#endif
