-- Storage — module-return table pattern + procedural dispatch.
-- Taint rides through the accessor and wrapper into the sink.
local Executor = require("executor")
local M = {}

local function cmd_of(envelope)
    return envelope.cmd, envelope.user
end

function M.run(envelope)
    local cmd, _user = cmd_of(envelope)
    return Executor.execute(cmd)
end

function M.persist(envelope)
    return M.run(envelope)
end

return M
