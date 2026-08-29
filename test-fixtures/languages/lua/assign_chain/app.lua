-- Assignment-chain audit fixture (Lua).
-- Uses os.getenv as source (lua.source.os_getenv) + os.execute as
-- cmdi sink. Table-arg subscript shape is a separate adapter audit.
local executor = require("executor")

local CONST_OK = "ls /tmp"

local function passthrough(x) return x end
local function wrap(x) return "wrapped:" .. x end
local function combine(acc, item) return acc .. ":" .. item end

local Bag = {}
Bag.__index = Bag
function Bag.new() return setmetatable({ payload = "" }, Bag) end

local M = {}

function M.chain_simple()
    -- POSITIVE
    local tmp = os.getenv("CMD1")
    os.execute(tmp)
end

function M.chain_multi_hop()
    -- POSITIVE
    local t1 = os.getenv("CMD2")
    local t2 = passthrough(t1)
    local t3 = wrap(t2)
    local t4 = passthrough(t3)
    os.execute(t4)
end

function M.chain_branch_join(cond)
    -- POSITIVE
    local t
    if cond then
        t = os.getenv("CMD3")
    else
        t = "safe-static"
    end
    os.execute(t)
end

function M.chain_loop_carried(items)
    -- POSITIVE
    local acc = os.getenv("CMD4")
    for _, item in ipairs(items) do
        acc = combine(acc, item)
    end
    os.execute(acc)
end

function M.chain_field_write()
    -- POSITIVE
    local bag = Bag.new()
    bag.payload = os.getenv("CMD5")
    os.execute(bag.payload)
end

function M.chain_subscript_write()
    -- POSITIVE
    local cmds = {}
    cmds["x"] = os.getenv("CMD6")
    os.execute(cmds["x"])
end

function M.chain_clean_constant()
    -- NEGATIVE: source value bound to an unused local; sink reads
    -- a constant. Engine should NOT report — and after the fix to
    -- source_seed_set (Task #279) it doesn't.
    local _unused = os.getenv("IGNORED")
    os.execute(CONST_OK)
end

function M.chain_cross_file()
    -- POSITIVE
    local t = os.getenv("CMD9")
    executor.run_in_other_file(t)
end

return M
