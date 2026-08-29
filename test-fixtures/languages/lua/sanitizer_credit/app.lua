local M = {}

function M.unsanitized()
    local t = os.getenv("CMD")
    os.execute(t)
end

function M.sanitized()
    local t = os.getenv("CMD")
    local safe = string.gsub(t, "[^%w_-]", "")
    os.execute(safe)
end

return M
