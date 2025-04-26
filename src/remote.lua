local aes = require "resty.aes"
local helper = require "helper"
local conf = require "config"
local bor = bit.bor
local lshift = bit.lshift

if not helper.check_config(conf) then
    return
end

-- set config parameters
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

local recv_buf = ""
local phase = 0
local target_sock = nil
local target_loop_thread = nil

-- set local connection
local local_sock, err = ngx.req.socket(true)
if not local_sock then
    ngx.log(ngx.ERR, "Failed to get local connection ", err)
    return
end
local_sock:settimeouts(c_timeout, w_timeout, r_timeout)

local function send_socks5_resp(resp) 
    return helper.pack_send(local_sock, resp, aes_128_cbc)
end

local function target_loop()
    while running do
        -- receive from target
        local raw, err = target_sock:receiveany(r_max_len)
        if not raw then
            -- ngx.log(ngx.ERR, "Failed to receive target data", err)
            running = false
            break
        end
        ngx.log(ngx.DEBUG, "target loop recv ", #raw)
        local bytes, err = helper.pack_send(local_sock, raw, aes_128_cbc)
        if not bytes then
            running = false
            break
        end
    end
    target_sock:close()
    target_loop_thread = nil
end

local function socks5(data) 
    if data and #data > 0 then
        if phase == 0 then
            -- auth
            ngx.log(ngx.DEBUG, "auth start")
            if #data < 3 then
                send_socks5_resp(string.char(0x05) .. string.char(0x01))
                return false
            end
            if string.sub(data, 1, 1) ~= string.char(0x05) then
                send_socks5_resp(string.char(0x05) .. string.char(0x01))
                return false
            end

            local bytes, err = send_socks5_resp(string.char(0x05) .. string.char(0x00))
            if not bytes then
                ngx.log(ngx.ERR, "Failed to send socks5 ", err) 
                return false
            end
            phase = 1
            ngx.log(ngx.DEBUG, "auth end")
            -- goto socks5_continue
        elseif phase == 1 then
            -- connect
            helper.print_hex("connect start ", data)
            if #data < 7 then
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end
            if string.sub(data, 1, 1) ~= string.char(0x05) then
                ngx.log(ngx.DEBUG, "connect 111")
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end
            local cmd = string.sub(data, 2, 2)
            if cmd ~= string.char(0x01) then
                ngx.log(ngx.DEBUG, "connect 222 ")
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end
            local target_host = nil
            local addr_len = 0
            local type = string.sub(data, 4, 4)
            if type == string.char(0x01) then
                -- IP
                ngx.log(ngx.DEBUG, "connect IP type")
                if #data < 10 then 
                    ngx.log(ngx.DEBUG, "connect 333")
                    send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                    return false
                end
                local ip1, ip2, ip3, ip4 = string.byte(data, 5, 8)
                target_host = ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4
                addr_len = 3
            elseif type == string.char(0x03) then
                -- domain
                ngx.log(ngx.DEBUG, "connect domain type")
                addr_len = string.byte(data, 5, 5)
                ngx.log(ngx.DEBUG, "connect domain type ", addr_len)
                if addr_len <= 0 then
                    ngx.log(ngx.DEBUG, "connect 444")
                    send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                    return false
                end
                if #data < 7 + addr_len then 
                    ngx.log(ngx.DEBUG, "connect 555")
                    send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                    return false
                end
                target_host = string.sub(data, 6, addr_len + 5)
            else
                ngx.log(ngx.DEBUG, "connect 666")
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end

            local port1, port2 = string.byte(data, 6 + addr_len, 7 + addr_len) 
            local target_port = bor(lshift(port1, 8), port2)
            ngx.log(ngx.DEBUG, "target_host:", target_host, " target_port:", target_port)

            -- connect target
            target_sock = ngx.socket.tcp()
            target_sock:settimeouts(c_timeout, w_timeout, r_timeout)
            local ok, err = target_sock:connect(target_host, target_port)
            if not ok then
                ngx.log(ngx.ERR, "Failed to connect to target host ", err)
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end

            target_loop_thread = ngx.thread.spawn(target_loop)
            ngx.log(ngx.DEBUG, "target_host:", target_host, " target_port:", target_port, " has been connected")

            local bytes, err = send_socks5_resp(string.char(0x05) .. string.char(0x00) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
            if not bytes then
                ngx.log(ngx.ERR, "Failed to send socks5 ", err) 
                return false
            end
            phase = 2
            ngx.log(ngx.DEBUG, "connect end")
            -- goto socks5_continue
        elseif phase == 2 then
            -- data
            helper.print_hex("data data ", data)
            local bytes, err = target_sock:send(data)
            if not bytes then
                -- ngx.log(ngx.ERR, "Failed to send data ", err)
                return false
            end
            ngx.log(ngx.DEBUG, "data sent ok ", bytes)
        end
    end
    return true
end

local function local_loop() 

    ::local_loop_continue::
    while running do
        -- receive from local
        local raw, err = local_sock:receiveany(r_max_len)
        if not raw then
            -- ngx.log(ngx.ERR, "Failed to receive local data", err)
            running = false
            break
        end

        ngx.log(ngx.DEBUG, "local loop raw ", #raw)
        recv_buf = (recv_buf or "") .. raw

        ngx.log(ngx.DEBUG, "local loop recv_buf ", #recv_buf)
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
            if not socks5(plain) then
                return false
            end
            return true
        end)

        if not ok then
            running = false
            break
        end
    end
end

-- start loop
local_loop()
if target_loop_thread then
    ngx.thread.kill(target_loop_thread)
end

