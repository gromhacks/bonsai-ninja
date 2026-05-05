local function executor(cmd)
    os.execute(cmd)
end

local function run_cb(cb, value)
    cb(value)
end

local function pass_to_callback()
    local t = os.getenv("CMD")
    run_cb(executor, t)
end

return { pass_to_callback = pass_to_callback }
