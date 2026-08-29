-- language_gauntlet Lua entry — reads one tainted HTTP query string, then dispatches
-- through a pipeline that exercises every idiomatic Lua flow construct
-- (multiple returns, varargs, closures, coroutines, metatables,
-- pcall, numeric/generic for, table constructors).
local Pipeline = require("core.pipeline")

local function handle_request()
    -- SOURCE — OpenResty's runtime-global request query string.
    local raw = ngx.var.args or ""
    local user = "remote"

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
