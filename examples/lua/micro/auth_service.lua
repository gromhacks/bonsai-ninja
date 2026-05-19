local M = {}
local luasql = require("luasql.sqlite3")
local db = luasql.sqlite3()

function M.verifyToken(token)
    local query = "SELECT user_id FROM tokens WHERE token = '" .. token .. "'"
    -- sink: SQL injection via concatenation
    db:execute(query)
    return 1
end

function M.runAdminCommand(user_id, cmd)
    if user_id then
        -- sink: command injection via shell concatenation
        os.execute("notify-admin " .. cmd)
    end
end

return M
