local aes = require "resty.aes"
local helper = require "helper"
local conf = require "config"

if not helper.check_config(conf) then
    return
end

-- set config parameters
local remote_host = conf.remote_host
local remote_port = conf.remote_port
local c_timeout = 60000
local w_timeout = 60000
local r_timeout = 60000
local running = true
local r_max_len = 1000 * 1024

local aes_128_cbc = nil
if conf.key and type(conf.key) == "string" and #conf.key > 0 then
    ngx.log(ngx.DEBUG, "Setup key")
    aes_128_cbc = aes:new(conf.key)
    if not aes_128_cbc then
        ngx.log(ngx.ERR, "Failed to init chiper ")
        return
    end
end

local remote_thread = nil 
local recv_buf = ""

-- set local connection
local local_sock, err = ngx.req.socket(true)
if not local_sock then
    ngx.log(ngx.ERR, "Failed to get local connection ", err)
    return
end
local_sock:settimeouts(c_timeout, w_timeout, r_timeout)

-- connect to remote
local remote_sock = ngx.socket.tcp()
remote_sock:settimeouts(c_timeout, w_timeout, r_timeout)
local ok, err = remote_sock:connect(remote_host, remote_port)
if not ok then
    ngx.log(ngx.ERR, "Failed to connect to remote server ", remote_host, ":", remote_port, " ", err) 
    return
end

local function local_loop() 
    while running do
        -- receive from local
        local raw, err = local_sock:receiveany(r_max_len)
        if not raw then
            -- ngx.log(ngx.ERR, "Failed to receive local data ", err)
            running = false
            break
        end
        
        local bytes, err = helper.pack_send(remote_sock, raw, aes_128_cbc)
        if not bytes then
            ngx.log(ngx.ERR, "Failed to send to remote ", err)
            running = false
            break
        end
    end
end

local function remote_loop() 

    ::remote_loop_continue::
    while running do
        -- receive from remote
        ngx.log(ngx.DEBUG, "remote loop ")
        local raw, err = remote_sock:receiveany(r_max_len)
        if not raw then
            -- ngx.log(ngx.ERR, "Failed to receive remote data ", err)
            running = false
            break
        end

        recv_buf = (recv_buf or "") .. raw

        -- unpack
        local ok
        ok, recv_buf = helper.unpack(recv_buf, function(payload)
            local plain = payload
            if aes_128_cbc then
                -- decrypt
                plain, err = aes_128_cbc:decrypt(payload)
                if not plain then
                    ngx.log(ngx.ERR, "Failed to decrypt ", err)
                    return false
                end
            end
            helper.print_hex("remote loop plain ", plain)
            -- send to local
            local bytes, err = local_sock:send(plain)
            if not bytes then
                ngx.log(ngx.ERR, "Failed to send to local ", err)
                return false
            end
            ngx.log(ngx.DEBUG, "remote loop send bytes ", bytes)
            return true
        end)

        if not ok then
            running = false
            break
        end
    end
    remote_thread = nil
end

-- start loop
remote_thread = ngx.thread.spawn(remote_loop)
local_loop()
if remote_thread then
    ngx.thread.kill(remote_thread)
end
-- close remote
remote_sock:close()

