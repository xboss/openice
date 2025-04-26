local resolver = require "resty.dns.resolver"
if resolver then
    ngx.say("resty.dns.resolver is available")
else
    ngx.say("resty.dns.resolver is NOT available")
end

local tcp = ngx.socket.tcp()

local domain = "www.bing.com"
-- 连接到目标主机
local ok, err = tcp:connect(domain, 80)
if not ok then
    ngx.say("Failed to connect: ", err)
    return
end

ngx.say("Connected successfully! ", domain)

tcp:close()
