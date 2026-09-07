local http = require('resty.http')
local pgmoon = require('pgmoon')
function direct()
  local input = ngx.req.get_uri_args()['url']
  local client = http.new()
  client:request_uri(input)
end
function database()
  local input = ngx.req.get_uri_args()['id']
  local pg = pgmoon.new({database='app'})
  pg:query('SELECT * FROM users WHERE id = ' .. input)
end
