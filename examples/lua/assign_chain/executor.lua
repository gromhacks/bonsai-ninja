local M = {}

function M.run_in_other_file(cmd)
    -- POSITIVE (cross-file)
    os.execute(cmd)
end

return M
