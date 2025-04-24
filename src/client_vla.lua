local sock5_gate = require "sock5_gate"
local config = require "config_vla"

local proxy_host = config.proxy_host
local proxy_port = config.proxy_port

ngx.log(ngx.DEBUG, "============================================================ new client connection ============================================================")
local gate = sock5_gate:new(proxy_host, proxy_port)
pcall(gate.start, gate)

ngx.exit(ngx.OK)
