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
local socks5_buf = ""
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
    -- local resp = string.char(0x05) .. string.char(cd) 
    -- .. string.char(0x00) .. string.char(0x01) 
    -- .. string.char(0x00) .. string.char(0x00) .. string.char(0x00)
    -- .. string.char(0x00) .. string.char(0x00) .. string.char(0x00)

    -- ngx.log(ngx.DEBUG, "send socks5 resp ", #resp)
    helper.print_hex("send socks5 resp ", resp)


    return helper.pack_send(local_sock, resp, aes_128_cbc)

    -- local encrypted = resp
    -- if aes_128_cbc then
    --     encrypted, err = aes_128_cbc:encrypt(resp)
    --     if not encrypted then
    --         ngx.log(ngx.ERR, "Failed to encrypt ", err)
    --         return 0, "Failed to encrypt"
    --     end
    -- end
    -- local msg = helper.pack(encrypted)
    -- if not msg then
    --     ngx.log(ngx.ERR, "Failed to pack")
    --     return 0, "Failed to pack"
    -- end
    -- return local_sock:send(msg)
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

        local bytes, err = helper.pack_send(local_sock, raw, aes_128_cbc)
        if bytes <= 0 then
            running = false
            break
        end
    end
    target_sock:close()
    target_loop_thread = nil
end

local function socks5(socks5_buf) 
    socks5_buf = socks5_buf .. socks5_buf
    ::socks5_continue::
    while socks5_buf and #socks5_buf > 0 do
        local socks5_buf_len = #socks5_buf
        if phase == 0 then
            -- auth
            ngx.log(ngx.DEBUG, "auth start")
            if #socks5_buf < 3 then
                return true
            end
            if string.sub(socks5_buf, 1, 1) ~= string.char(0x05) then
                send_socks5_resp(string.char(0x05) .. string.char(0x01))
                return false
            end

            local bytes, err = send_socks5_resp(string.char(0x05) .. string.char(0x00))
            if bytes <= 0 then
                ngx.log(ngx.ERR, "Failed to send socks5 ", err) 
                return false
            end
            if socks5_buf_len > 3 then
                socks5_buf = string.sub(socks5_buf, 4, socks5_buf_len)
            else 
                assert(socks5_buf_len == 3)
                socks5_buf = nil
            end
            phase = 1
            ngx.log(ngx.DEBUG, "auth end")
            goto socks5_continue
        elseif phase == 1 then
            -- connect
            ngx.log(ngx.DEBUG, "connect start")
            helper.print_hex("connect socks5_buf ", socks5_buf)
            if #socks5_buf < 7 then
                return true
            end
            if string.sub(socks5_buf, 1, 1) ~= string.char(0x05) then
                ngx.log(ngx.DEBUG, "connect 111")
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end
            local cmd = string.sub(socks5_buf, 2, 2)
            if cmd ~= string.char(0x01) then
                ngx.log(ngx.DEBUG, "connect 222 ")
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end
            local target_host = nil
            local addr_len = 0
            local type = string.sub(socks5_buf, 4, 4)
            if type == string.char(0x01) then
                -- IP
                ngx.log(ngx.DEBUG, "connect IP type")
                if #socks5_buf < 10 then 
                    ngx.log(ngx.DEBUG, "connect 333")
                    send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                    return false
                end
                local ip1, ip2, ip3, ip4 = string.byte(socks5_buf, 5, 8)
                target_host = ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4
                addr_len = 3
            elseif type == string.char(0x03) then
                -- domain
                ngx.log(ngx.DEBUG, "connect domain type")
                addr_len = string.byte(socks5_buf, 5, 5)
                ngx.log(ngx.DEBUG, "connect domain type ", addr_len)
                if addr_len <= 0 then
                    ngx.log(ngx.DEBUG, "connect 444")
                    send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                    return false
                end
                if #socks5_buf < 7 + addr_len then 
                    ngx.log(ngx.DEBUG, "connect 555")
                    send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                    return false
                end
                target_host = string.sub(socks5_buf, 6, addr_len + 6)
            else
                ngx.log(ngx.DEBUG, "connect 666")
                send_socks5_resp(string.char(0x05) .. string.char(0x01) .. string.char(0x00) .. string.char(0x01) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00) .. string.char(0x00))
                return false
            end

            local port1, port2 = string.byte(socks5_buf, 6 + addr_len, 7 + addr_len) 
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
            if bytes <= 0 then
                ngx.log(ngx.ERR, "Failed to send socks5 ", err) 
                return false
            end
            -- reset socks5_buf
            if socks5_buf_len > 7 + addr_len then
                socks5_buf = string.sub(socks5_buf, 8 + addr_len, socks5_buf_len)
            else 
                assert(socks5_buf_len == 7 + addr_len)
                socks5_buf = nil
            end
            phase = 2
            ngx.log(ngx.DEBUG, "connect end")
            goto socks5_continue
        elseif phase == 2 then
            -- data
            local bytes, err = helper.pack_send(local_sock, socks5_buf, aes_128_cbc)
            if bytes < socks5_buf_len then
                socks5_buf = string.sub(socks5_buf, bytes + 1, socks5_buf_len)
            else
                socks5_buf = nil
                ngx.log(ngx.DEBUG, "connect data ", socks5_but_len, " ", bytes)
                assert(socks5_buf_len == bytes)
            end
            phase = 3
            goto socks5_continue
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

        recv_buf = recv_buf .. raw
        local recv_buf_len = #recv_buf

        -- unpack
        local remain_len = helper.unpack_header(recv_buf)
        if remain_len < 4 or remain_len > r_max_len * 10 then
            ngx.log(ngx.ERR, "Invalid msg length from local len: ", remain_len)
            running = false
            break
        end
        
        local payload = nil
        if remain_len + 4 == recv_buf_len then
            payload = string.sub(recv_buf, 5, 4 + remain_len)
            recv_buf = ""
        elseif remain_len + 4 < recv_buf_len then
            payload = string.sub(recv_buf, 5, 4 + remain_len)
            recv_buf = string.sub(recv_buf, 5 + remain_len, recv_buf_len)
            assert(#payload + #recv_buf == recv_buf_len) -- TODO: delete
        elseif remain_len + 4 > recv_buf_len then
            goto local_loop_continue
        end

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
        if not socks5(plain) then
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

