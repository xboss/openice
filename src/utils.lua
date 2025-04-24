
local resty_aes = require "resty.aes"
local resty_str = require "resty.string"
local config = require "config"

local _M = {}

local aes_128_cbc_md5 = assert(resty_aes:new(config.aes_key))
local aes_256_cbc_sha512x5 = assert(resty_aes:new(config.aes_key, config.aes_salt, resty_aes.cipher(256,"cbc"), resty_aes.hash.sha512, 5))
local aes_128_cbc_with_iv = assert(resty_aes:new(config.aes_key, nil, resty_aes.cipher(128,"cbc"), {iv=config.aes_iv}))
local level = config.aes_level or 0

function _M.aes_encrypt(s)
    if level == 0 then
        local encrypted = aes_128_cbc_md5:encrypt(s)
        return encrypted
    elseif level == 1 then
        local encrypted = aes_256_cbc_sha512x5:encrypt(s)
        return encrypted
    elseif level == 2 then
        local encrypted = aes_128_cbc_with_iv:encrypt(s)
        return encrypted
    else
        return s
    end
end

function _M.aes_decrypt(s)
    if level == 0 then
        return aes_128_cbc_md5:decrypt(s)
    elseif level == 1 then
        return aes_256_cbc_sha512x5:decrypt(s)
    elseif level == 2 then
        return aes_128_cbc_with_iv:decrypt(s)
    else
        return s
    end
end

return _M