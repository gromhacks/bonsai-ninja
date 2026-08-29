local executor = require("executor")

local M = {}

function M.transform_and_forward(value)
    local upper = string.upper(value)
    executor.execute(upper)
end

return M
