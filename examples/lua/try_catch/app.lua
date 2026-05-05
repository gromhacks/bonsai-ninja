-- Lua uses pcall.
local M = {}
function M.tainted_through_try()
    local ok, t = pcall(function() return os.getenv("CMD") end)
    if not ok then t = "" end
    os.execute(t)
end
return M
