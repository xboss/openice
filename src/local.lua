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
        if bytes <= 0 then
            ngx.log(ngx.ERR, "Failed to send to remote ", err)
            running = false
            break
        end

        -- local encrypted = raw
        -- if aes_128_cbc then
        --     -- encrypt
        --     encrypted, err = aes_128_cbc:encrypt(raw)
        --     if not encrypted then
        --         ngx.log(ngx.ERR, "Failed to encrypt ", err)
        --         running = false
        --         break
        --     end
        -- end
        -- -- pack
        -- local msg = helper.pack(encrypted)
        -- if not msg then
        --     ngx.log(ngx.ERR, "Invalid msg from local")
        --     running = false
        --     break
        -- end
        -- -- send to remote
        -- local bytes, err = remote_sock:send(msg)
        -- if bytes <= 0 then
        --     ngx.log(ngx.ERR, "Failed to send to remote ", err)
        --     running = false
        --     break
        -- end

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

        recv_buf = recv_buf .. raw
        local recv_buf_len = #recv_buf

        ngx.log(ngx.DEBUG, "remote loop recv_buf_len ", recv_buf_len )

        -- unpack
        local remain_len = helper.unpack_header(recv_buf)
        if remain_len < 4 or remain_len > r_max_len * 10 then
            ngx.log(ngx.ERR, "Invalid msg length from remote len: ", remain_len)
            running = false
            break
        end
        
        ngx.log(ngx.DEBUG, "remote loop remain_len ", remain_len)

        local payload = nil
        if remain_len + 4 == recv_buf_len then
            payload = string.sub(recv_buf, 5, 4 + remain_len)
            recv_buf = ""
        elseif remain_len + 4 < recv_buf_len then
            payload = string.sub(recv_buf, 5, 4 + remain_len)
            recv_buf = string.sub(recv_buf, 5 + remain_len, recv_buf_len)
            ngx.log(ngx.DEBUG, "remote loop ", #payload, " ", #recv_buf, " ", recv_buf_len)

            assert(#payload + #recv_buf == recv_buf_len) -- TODO: delete
        elseif remain_len + 4 > recv_buf_len then
            goto remote_loop_continue
        end

        ngx.log(ngx.DEBUG, "remote loop payload ", #payload)

        local plain = payload
        if aes_128_cbc then
            -- decrypt
            plain, err = aes_128_cbc:decrypt(payload)
            if not plain then
                ngx.log(ngx.ERR, "Failed to decrypt ", err)
                running = false
                break
            end
        end

        helper.print_hex("remote loop plain ", plain)

        -- send to local
        local bytes, err = local_sock:send(plain)
        if bytes <= 0 then
            ngx.log(ngx.ERR, "Failed to send to local ", err)
            running = false
            break
        end

        ngx.log(ngx.DEBUG, "remote loop send bytes ", bytes)

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

