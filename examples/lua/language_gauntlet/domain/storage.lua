-- Storage — module-return table pattern + procedural dispatch.
-- Taint rides through the accessor and wrapper into the sink.
local Executor = require("runtime.executor")
local M = {}

local Repository = {}
Repository.__index = Repository

function Repository.new(envelope)
    local self = setmetatable({}, Repository)
    self.data = envelope
    return self
end

function Repository:cmd_of()
    return self.data.cmd, self.data.user
end

function Repository.run(envelope)
    -- Table construction plus whole-value and projected aliases stay on the
    -- canonical path; the separate factory/colon methods above exercise Lua's
    -- metatable receiver semantics without making runtime execution depend on
    -- a guessed class hierarchy.
    local holder = { data = envelope }
    local alias = holder
    local projected = alias.data.cmd
    local cmd = envelope.cmd
    if projected ~= nil then
        cmd = projected
    end
    return Executor.execute(cmd)
end

function M.persist(envelope)
    return Repository.run(envelope)
end

return M
