local transformer = require("transformer")

local M = {}

function M.run_pipeline(payload)
    local wrapped = "[" .. payload .. "]"
    transformer.transform_and_forward(wrapped)
end

return M
