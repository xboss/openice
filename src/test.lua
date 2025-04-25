local aes = require "resty.aes"
local helper = require "helper"
local conf = require "config"

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

-- set local connection
local local_sock, err = ngx.req.socket(true)
if not local_sock then
    ngx.log(ngx.ERR, "Failed to get local connection ", err)
    return
end
local_sock:settimeouts(c_timeout, w_timeout, r_timeout)

local function local_loop() 
    while running do
        -- receive from local
        local raw, err = local_sock:receiveany(r_max_len)
        if not raw then
            -- ngx.log(ngx.ERR, "Failed to receive local data ", err)
            running = false
            break
        end

        local encrypted = raw
        if aes_128_cbc then
            -- encrypt
            encrypted, err = aes_128_cbc:encrypt(raw)
            if not encrypted then
                ngx.log(ngx.ERR, "Failed to encrypt ", err)
                running = false
                break
            end
            ngx.log(ngx.DEBUG, "encrypted: ", #encrypted, " raw: ", #raw)
        end
        
        -- pack
        local msg = helper.pack_msg(encrypted)
        if not msg then
            ngx.log(ngx.ERR, "Invalid msg from local")
            running = false
            break
        end
        -- unpack
        local payload, msg_len = helper.unpack_msg(msg)
        if not payload or msg_len <= 4 then
            ngx.log(ngx.ERR, "Invalid msg from remote")
            running = false
            break
        end
        ngx.log(ngx.DEBUG, "msg_len:", msg_len)
        assert(payload == encrypted)
        assert(msg_len + 4 == #msg)


        local plain = encrypted
        if aes_128_cbc then
            -- decrypt
            plain, err = aes_128_cbc:decrypt(encrypted)
            if not plain then
                ngx.log(ngx.ERR, "Failed to decrypt ", err)
                running = false
                break
            end
            assert(plain == raw)
            ngx.log(ngx.DEBUG, "plain len: ", #plain, " plain: ", plain)
        end


        local_sock:send(raw) 

        -- unpack
        
        -- decrypt

        --local encrypted = raw
        --if aes_128_cbc then
        --    -- encrypt
        --    encrypted, err = aes_128_cbc:encrypt(raw)
        --    if not encrypted then
        --        ngx.log(ngx.ERR, "Failed to encrypt ", err)
        --        running = false
        --        break
        --    end
        --end
        ---- pack
        --local msg = helper.pack_msg(encrypted)
        --if not msg then
        --    ngx.log(ngx.ERR, "Invalid msg from local")
        --    running = false
        --    break
        --end

        --local bytes, err = remote_sock:send(msg)
        --if not bytes then
        --    ngx.log(ngx.ERR, "Failed to send to remote ", err)
        --    running = false
        --    break
        --end

    end
end

-- start loop
local_loop()


