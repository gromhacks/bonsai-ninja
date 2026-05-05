-- mega_flow Lua entry — reads one tainted stdin line, then dispatches
-- through a pipeline that exercises every idiomatic Lua flow construct
-- (multiple returns, varargs, closures, coroutines, metatables,
-- pcall, numeric/generic for, table constructors).
local Pipeline = require("pipeline")

local function handle_request()
    -- SOURCE — io.read reads one tainted stdin line.
    -- Matched by lua.source.io_read (call-kind, name=read).
    local raw = io.read("*l") or ""
    local user = os.getenv("USER") or "anon"

    -- Table constructor + string concat — taint rides the envelope.
    local envelope = {
        kind = "run",
        cmd = "" .. raw,
        user = user,
        length = #raw,
        extras = { raw },
    }

    return Pipeline.orchestrate(envelope)
end

print(handle_request())
