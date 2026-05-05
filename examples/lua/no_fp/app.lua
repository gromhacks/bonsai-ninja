local CONST_OK = "ls /tmp"

local M = {}

function M.decoy()
    local _unused = os.getenv("IGNORED")
    os.execute(CONST_OK)
end

function M.unrelated_chain()
    local a = "hello"
    return string.upper(a)
end

return M
