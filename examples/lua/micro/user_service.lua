local auth = require("auth_service")

local M = {}

function M.getUser(token)
    return auth.verifyToken(token)
end

function M.updateUser(token, action)
    local user_id = auth.verifyToken(token)
    if user_id then
        auth.runAdminCommand(user_id, action)
    end
    return user_id
end

return M
