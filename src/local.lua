-- set config parameters
local remote_host = "127.0.0.1"
local remote_port = "7778"
local c_timeout = 60000
local w_timeout = 60000
local r_timeout = 60000
local running = true
local ok = err = nil

-- set local connection
local local_sock, err = ngx.req.socket(true)
if not local_sock then
    ngx.log(ngx.ERR, "Failed to get local connection ", err)
    return
end
local_sock:settimeout(c_timeout, w_timeout, r_timeout)

-- connect to remote
local remote_sock = ngx.socket.tcp()
remote_sock:settimeouts(c_timeout, w_timeout, r_timeout)
ok, err = remte_sock:connect(remote_host, remote_port)
if not ok then
    ngx.log(ngx.ERR, "Failed to connect to remote server ", remote_host, ":", remote_port, " ", err) 
    return
end

-- receive loop
while running do

end
-- send to remote
-- close remote

