local bit = require "bit"
local cjson = require "cjson.safe"
local bp = require "base_protocol"
local tcp_conn = require "tcp_connection"

local encode_json = cjson.encode
local decode_json = cjson.decode

local str_byte = string.byte
local str_char = string.char
local str_sub = string.sub
local str_len = string.len

local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift

local _M = {}
local mt = { __index = _M }

local function connectdown()
    local down_sock, err = tcp_conn:new()
    local down_conn = down_sock:start()
    assert(down_conn)
    ngx.log(ngx.DEBUG, "++++++ connect down ok ")
    return down_sock
end

function _M:new()
    return setmetatable({
        down_conn = nil,
        down_phase = 0, -- 0:初始连接阶段；1：认证阶段；2：命令阶段；3：自由通信阶段；
        up_conn = nil,
        -- up_host = up_host,
        -- up_port = up_port,
        up_conn_timeout = 60000,
        up_send_timeout = 60000,
        up_read_timeout = 60000,
        is_up_close = true,
        is_down_close = true,
        up_loop_thread = nil,
    }, mt)
end

function _M:connectup(up_host, up_port)
    self.up_conn = ngx.socket.tcp()
    self.up_conn:settimeouts(self.up_conn_timeout, self.up_send_timeout, self.up_read_timeout)
    local ok, err = self.up_conn:connect(up_host, up_port)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect ", up_host, " : ", up_port, " ", err)
        return nil, err
    end
    assert(self.up_conn)
    self.is_up_close = false
    ngx.log(ngx.DEBUG, "successfully connected to upstream!")
    return self.up_conn
end

function _M:send_to_up(s)
    if not self.up_conn or self.is_up_close then
        ngx.log(ngx.WARN, "upstream is closed")
        return nil, "upstream is closed"
    end
    local bytes, err = self.up_conn:send(s)
    if not bytes then
        ngx.log(ngx.ERR, "send_to_up failed to send ", err)
        return nil, err
    end
    return bytes, err
end

function _M:send_to_down(o)
    if not self.down_conn or self.is_down_close then
        ngx.log(ngx.WARN, "downstream is closed")
    end
    local bytes, err = self.down_conn:send(o)
    if not bytes then
        ngx.log(ngx.ERR, "send_to_down failed to send ", err)
        return
    end
end

function _M:down_loop()
    ngx.log(ngx.DEBUG, "++++++ down_loop start ")
    while not self.is_down_close do
        -- 收消息
        assert(self.down_conn)
        local msg, err = self.down_conn:recv()
        if not msg then
            ngx.log(ngx.ERR, "down_loop msg error ", err)
            -- TODO: 是否continue
            self.is_down_close = true
            return
        end
        -- ngx.log(ngx.DEBUG, "++++++", encode_json(msg))
        if not msg.cmd then
            ngx.log(ngx.ERR, "down_loop msg.cmd error ")
            self.is_down_close = true
            return
        end
        if msg.cmd == "connect" then
            if not msg.host or not msg.port then
                ngx.log(ngx.ERR, "down_loop connect cmd error ")
                self.is_down_close = true
                return
            end
            local up_conn = self:connectup(msg.host, msg.port)
            if not up_conn then
                self.is_down_close = true
                return
            end
            -- 启动上游协程
            self.up_loop_thread = ngx.thread.spawn(self.up_loop, self)
            ngx.log(ngx.DEBUG, "++++++ connect ok")
        elseif msg.cmd == "proxy" then
            ngx.log(ngx.DEBUG, "++++++ proxy start")
            self:send_to_up(msg.payload)
            ngx.log(ngx.DEBUG, "++++++ proxy ok")
        else
            ngx.log(ngx.ERR, "down_loop cmd error ")
            self.is_down_close = true
            return
        end
    end
    self.is_down_close = true
    return
end

function _M:up_loop()
    ngx.log(ngx.DEBUG, "++++++ up_loop start ")
    ::continue::
    while not self.is_up_close do
        local raw, err = self.up_conn:receiveany(102400)
        if err == "timeout" then
            ngx.log(ngx.DEBUG, "------ up_loop read timeout")
            goto continue
        end
        if not raw then
            ngx.log(ngx.WARN, "up_loop msg error ", err)
            -- TODO: 是否continue
            self.is_up_close = true
            return
        end
        -- ngx.log(ngx.DEBUG, "++++++ up_loop raw ", raw)
        local msg = {
            cmd = "proxy",
            payload = raw
        }
        self:send_to_down(msg)
    end
    self.is_down_close = true
end

function _M:start()
    ngx.log(ngx.DEBUG, "++++++ proxy gate start ")
    self.down_conn = connectdown()
    self.is_down_close = false

    -- 启动下游循环
    -- local ok, err = pcall(self.down_loop, self)
    -- if not ok then
    --     ngx.log(ngx.ERR, "down_loop error ", err)
    -- end
    self:down_loop()
    ngx.log(ngx.DEBUG, "++++++ proxy gate down_loop end")

    self.is_down_close = true

    self.is_up_close = true
    if self.up_loop_thread then
        ngx.thread.kill(self.up_loop_thread)
    end


    -- 安全关闭连接
    self.down_conn:close()
    self.up_conn:close()

    ngx.log(ngx.DEBUG, "++++++ proxy gate end")
end

return _M
