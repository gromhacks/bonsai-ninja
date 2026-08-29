-- Complex Lua fixture: tables, closures, pcall, loops.

local M = {}

function M.findUser(users, id)
    if users[id] then
        return users[id]
    end
    return nil
end

function M.loadAllUsers()
    local users = {}
    local ok, err = pcall(function()
        for i = 1, 10 do
            users[i] = "user_" .. i
        end
    end)
    if not ok then
        print("load failed: " .. tostring(err))
        return nil
    end
    return users
end

function M.escapeSQL(input)
    return string.gsub(input, "'", "''")
end

function M.dispatchToken(token)
    if token == "" then
        return
    elseif string.sub(token, 1, 6) == "admin_" then
        M.runAdmin(token)
    else
        M.runUser(token)
    end
end

function M.processBatch(tokens)
    for _, token in ipairs(tokens) do
        M.dispatchToken(token)
    end
end

function M.runAdmin(token)
    os.execute("admin-task " .. token)
end

function M.runUser(token)
    os.execute("user-task " .. token)
end

return M
