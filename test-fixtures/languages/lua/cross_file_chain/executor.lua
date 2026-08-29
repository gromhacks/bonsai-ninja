local M = {}

function M.execute(cmd)
    -- POSITIVE (terminal cross-file sink)
    os.execute(cmd)
end

return M
