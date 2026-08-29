-- Receiver-type audit fixture (Lua).
-- os.execute — module-attribute receiver. The new
-- lua.sqli.method_execute_concat rule fires receiver-agnostic
-- on `:execute` method calls.

local function handle()
    -- POSITIVE
    local tainted = os.getenv("CMD")
    os.execute(tainted)
end

return { handle = handle }
