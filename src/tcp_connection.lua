local bit = require "bit"
local bp = require "base_protocol"
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

-- local str_unpack = string.unpack

local _M = {}
local mt = { __index = _M }

function _M:new(opts)
    opts = opts or {
        conn_timeout = 60000,
        send_timeout = 60000,
        read_timeout = 60000,
    }
    return setmetatable({
        opts = opts,
        close_flg = 0, -- 连接是否关闭的标识，1表示关闭，0表示未关闭
    }, mt)
end

function _M:start(host, port)
    local err
    if host and port then
        self.sock = ngx.socket.tcp()
        local ok
        ok, err = self.sock:connect(host, port)
        if not ok then
            ngx.log(ngx.ERR, "failed to connect ", host, " : ", port, " ", err)
            return nil, err
        end
    else
        self.sock, err = ngx.req.socket(true)
    end
    assert(self.sock)
    self.sock:settimeouts(self.opts.conn_timeout, self.opts.send_timeout, self.opts.read_timeout)
    self.close_flg = 1
    return self.sock, err
end

function _M:send(obj)
    local bytes, err = self.sock:send(bp.encode(obj))
    if not bytes then
        ngx.log(ngx.ERR, "tcp_server failed to send ", err)
        return nil, err
    end

    return bytes, err
end

function _M:recv()

    local remain_len_s = ""
    local remain_len_recv_s, err, partial = self.sock:receive(4)
    if err == "timeout" then
        remain_len_s = partial .. remain_len_s
    end
    remain_len_s = remain_len_s .. remain_len_recv_s
    if not remain_len_s then
        ngx.log(ngx.ERR, "sock recv remain_len error ", err)
        return nil, err
    end

    -- 计算剩余长度
    local len1, len2, len3, len4 = str_byte(remain_len_s, 1, 4)
    local remain_len = bxor(lshift(len1, 24), bxor(lshift(len2, 16), bxor(lshift(len3, 8), len4)))
    -- local remain_len, _ = str_unpack(">I4", remain_len_s)

    ngx.log(ngx.DEBUG, "sock recv remain_len ", remain_len)
    local remain_data
    remain_data, err, partial = self.sock:receive(remain_len)
    if not remain_data then
        ngx.log(ngx.ERR, "sock recv remain_data error ", err, " partial ", partial)
        return nil, err
    end

    local frame = remain_len_s .. remain_data
    local msg = bp.decode(frame)

    return msg
end

function _M:close()
    if self.close_flg == 0 then
        self.sock:close()
        self.close_flg = 1
    end
end

return _M