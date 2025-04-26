local bit = require "bit"

local _M = {}

function _M.check_config(conf)
    if not conf then
        ngx.log(ngx.ERR, "Invalid config")
        return false
    end
    if not conf.remote_host or type(conf.remote_host) ~= "string" or #conf.remote_host <= 0 then
        ngx.log(ngx.ERR, "Invalid remote_host in config")
        return false
    end
    if type(conf.remote_port) ~= "number" or conf.remote_port <=0 or conf.remote_port >= 65535 then
        ngx.log(ngx.ERR, "Invalid remote_port in config")
        return false
    end
    return true
end

function _M.pack(payload)
    local payload_len = #payload
    local len_bytes = {
        string.char(bit.band(bit.rshift(payload_len, 24), 0xFF)),
        string.char(bit.band(bit.rshift(payload_len, 16), 0xFF)),
        string.char(bit.band(bit.rshift(payload_len, 8), 0xFF)),
        string.char(bit.band(payload_len, 0xFF))
    }
    return table.concat(len_bytes) .. payload
end

function _M.unpack_header(data)
    if #data < 4 then
        ngx.log(ngx.ERR, "Invalid data: too short to contain length field")
        return 0
    end

    local len_byte1 = string.byte(data, 1)
    local len_byte2 = string.byte(data, 2)
    local len_byte3 = string.byte(data, 3)
    local len_byte4 = string.byte(data, 4)

    local payload_len = bit.bor(
        bit.lshift(len_byte1, 24),
        bit.lshift(len_byte2, 16),
        bit.lshift(len_byte3, 8),
        len_byte4
    )
    return payload_len 
end

function _M.pack_send(sock, raw, aes)
    local encrypted = raw
    local err
    if aes then
        encrypted, err = aes:encrypt(raw)
        if not encrypted then
            ngx.log(ngx.ERR, "Failed to encrypt ", err)
            return 0, "Failed to encrypt"
        end
    end
    local msg = _M.pack(encrypted)
    ngx.log(ngx.DEBUG, "pack send msg ", #msg)
    if not msg then
        ngx.log(ngx.ERR, "Failed to pack")
        return 0, "Failed to pack"
    end
    return sock:send(msg)
end

function _M.unpack(msg, did_unpack_cb)
    local pending_buf = msg

    ::more_unpack::
    ngx.log(ngx.DEBUG, "unpack pending_buf ", #pending_buf)

    local pending_buf_len = #pending_buf
    local remain_len = _M.unpack_header(pending_buf)
    if remain_len < 4 or remain_len > 10240000 then -- TODO: Magic number
        ngx.log(ngx.ERR, "Invalid msg length from remote len: ", remain_len)
        return false
    end

    ngx.log(ngx.DEBUG, "unpack remain_len ", remain_len)

    local payload = nil
    if remain_len + 4 == pending_buf_len then
        payload = string.sub(pending_buf, 5, 4 + remain_len)
        if not did_unpack_cb(payload) then
            return false
        end
        return true
    elseif remain_len + 4 < pending_buf_len then
        payload = string.sub(pending_buf, 5, 4 + remain_len)
        pending_buf = string.sub(pending_buf, 5 + remain_len, pending_buf_len)
        ngx.log(ngx.DEBUG, "unpack more ", #payload, " ", #pending_buf)
        if not did_unpack_cb(payload) then
            return false
        end
        -- assert(4 + #payload + #pending_buf == pending_buf_len) -- TODO: delete
        goto more_unpack
    end
    -- remain_len + 4 > pending_buf_len 
    ngx.log(ngx.DEBUG, "unpack pending ", remain_len, " ", pending_buf_len)
    return true, pending_buf 
end

function _M.print_hex(prefix, data)
    local hex = data:gsub(".", function(c)
        return string.format("%02X ", string.byte(c))
    end)
    ngx.log(ngx.DEBUG, prefix, hex)
end

return _M
