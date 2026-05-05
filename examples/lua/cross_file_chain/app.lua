-- Cross-file argument flow audit fixture (Lua).
local pipeline = require("pipeline")

local M = {}

function M.handler()
    -- POSITIVE
    local user = os.getenv("CMD")
    pipeline.run_pipeline(user)
end

function M.handler_split()
    -- POSITIVE
    local user = os.getenv("FROM")
    local flag = os.getenv("FLAG")
    pipeline.run_pipeline(user .. ":" .. flag)
end

return M
