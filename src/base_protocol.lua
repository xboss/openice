
local bit = require "bit"
local ffi = require "ffi"
local cjson = require "cjson.safe"
local utils = require "utils"

local str_byte = string.byte
local str_char = string.char
local str_sub = string.sub
local str_len = string.len
local str_unpack = string.unpack
local str_pack = string.pack
local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift
local ffi_new = ffi.new
local ffi_string = ffi.string
local encode_json = cjson.encode
local decode_json = cjson.decode


local _M = {}

function _M.encode(obj)
    if not obj or type(obj) ~= "table" then
        ngx.log(ngx.ERR, "base protocol encode obj error")
        return nil, "base protocol encode obj error"
    end

    
    local payload = encode_json(obj)

    -- 加密
    payload = utils.aes_encrypt(payload, 1)

    local payload_len = str_len(payload)

    local remain_len = payload_len

    

    local raw = str_char(band(rshift(remain_len, 24), 0x000000ff))
            .. str_char(band(rshift(remain_len, 16), 0x000000ff))
            .. str_char(band(rshift(remain_len, 8), 0x000000ff))
            .. str_char(band(remain_len, 0x000000ff))
            .. payload

    return raw
end

function _M.decode(raw)
    if raw == nil or raw == "" then
        return nil, "bad raw data"
    end

    local len1, len2, len3, len4 = str_byte(raw, 1, 4)
    -- 计算剩余长度
    local remain_len = bxor(lshift(len1, 24), bxor(lshift(len2, 16), bxor(lshift(len3, 8), len4)))

    -- 计算payload长度
    local payload_len = remain_len
    if payload_len == 0 then
        return ""
    end

    local payload = str_sub(raw, 5, payload_len + 5)

    -- 解密
    payload = utils.aes_decrypt(payload, 1)

    local obj = decode_json(payload)
    return obj
end

return _M