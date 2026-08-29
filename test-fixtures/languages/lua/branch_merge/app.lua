local M = {}
function M.taint_one_leg(cond)
    local x
    if cond then x = os.getenv("CMD")
    else x = "safe-static" end
    os.execute(x)
end
function M.taint_overwritten(cond)
    local x = os.getenv("CMD")
    if cond then x = "clean-then"
    else x = "clean-else" end
    os.execute(x)
end
return M
