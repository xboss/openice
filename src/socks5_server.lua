local sock5 = require "socks5"

ngx.log(ngx.DEBUG, "sock5 server start...")
local s5 = sock5:new()
pcall(s5.start, s5)

ngx.exit(ngx.OK)