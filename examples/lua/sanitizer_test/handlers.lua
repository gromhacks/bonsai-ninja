-- Lua sanitizer-fixture — parallel handlers per sink family.
local ngx = require("ngx")

-- --- Command injection ------------------------------------------------

local function cmd_raw(input)
    return os.execute("ping " .. input)
end

local function cmd_safe(input)
    -- ngx.quote_sql_str is canonical OpenResty SQL escape but also
    -- suffices for shell argv in single-quote form.
    local safe = ngx.quote_sql_str(input)
    return os.execute("ping " .. safe)
end

-- --- XSS --------------------------------------------------------------

local function xss_raw(name)
    return "<p>Hello, " .. name .. "</p>"
end

local function xss_safe(name)
    local html = require("lapis.html")
    local safe = html.escape(name)
    return "<p>Hello, " .. safe .. "</p>"
end

-- --- Open redirect ----------------------------------------------------

local function redirect_safe(target)
    local safe = ngx.escape_uri(target)
    return "/next?to=" .. safe
end

return {
    cmd_raw = cmd_raw,
    cmd_safe = cmd_safe,
    xss_raw = xss_raw,
    xss_safe = xss_safe,
    redirect_safe = redirect_safe,
}
