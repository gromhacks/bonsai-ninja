local M = {}

function M.execute(cmd)
    -- SINK — os.execute · lua.cmdi.os_execute · CWE-78
    os.execute(cmd)
    return cmd
end

function M.clean_twin()
    -- NEGATIVE — same sink kind with a constant argument must not report.
    os.execute("echo clean")
    return "clean"
end

return M
