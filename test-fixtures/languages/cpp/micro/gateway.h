#ifndef GATEWAY_H
#define GATEWAY_H

#include <string>
#include <map>

namespace micro {

std::string handle_request(const std::map<std::string, std::string>& params);

}

#endif
