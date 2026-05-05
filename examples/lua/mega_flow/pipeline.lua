-- Pipeline — exercises Lua's idiomatic flow constructs: closures,
-- multiple returns, varargs, numeric / generic for, coroutines,
-- string.gmatch iterators, pcall (try/catch), metatables, dispatch
-- tables, and chained string.* calls.
local Storage = require("storage")
local M = {}

-- Coroutine producer — yields every tainted token to the caller.
local function tokenize(cmd)
    return coroutine.wrap(function()
        for word in string.gmatch(cmd, "%S+") do
            coroutine.yield(word)
        end
    end)
end

-- Closure factory — returns a reducer that joins tokens with `sep`.
local function make_joiner(sep)
    return function(acc, tok)
        if acc == "" then
            return tok
        else
            return acc .. sep .. tok
        end
    end
end

function M.orchestrate(envelope, ...)
    local extra = { ... }
    local cmd = envelope.cmd
    local user = envelope.user

    -- Generic-for iterator over the coroutine.
    local parts = {}
    for word in tokenize(cmd) do
        parts[#parts + 1] = word
    end

    -- Numeric-for + closure reduce — taint rides the accumulator.
    local joiner = make_joiner(" ")
    local joined = ""
    for i = 1, #parts do
        joined = joiner(joined, parts[i])
    end

    -- Dispatch table (Lua's pattern-match analogue).
    local routes = {
        run  = function(s) return "" .. s end,
        ["eval"] = function(s) return s:gsub("^%s+", ""):gsub("%s+$", "") end,
    }
    local route = routes[envelope.kind] or function(s) return s end
    local routed = route(joined)

    -- pcall (Lua's try/catch) — taint survives the branch.
    local ok, valid = pcall(function()
        assert(#routed > 0, "empty")
        return { kind = envelope.kind, cmd = routed, user = user, length = #routed, extras = extra or envelope.extras }
    end)
    if not ok then
        valid = { kind = envelope.kind, cmd = routed or "", user = user, length = 0, extras = {} }
    end
    setmetatable(valid, { __index = { cmd_value = function(self) return self.cmd end } })

    return Storage.persist(valid)
end

return M
