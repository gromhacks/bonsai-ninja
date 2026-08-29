local user_service = require("user_service")

local M = {}

function M.handleRequest(token, action)
    local user = user_service.getUser(token)
    local result = user_service.updateUser(token, action)
    return {user = user, result = result}
end

return M
