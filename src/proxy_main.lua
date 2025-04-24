local proxy_gate = require "proxy_gate"

ngx.log(ngx.DEBUG, "========== new proxy connection ")
local gate = proxy_gate:new()
pcall(gate.start, gate)

ngx.exit(ngx.OK)