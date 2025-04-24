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
    local down_sock, err = ngx.req.socket(true)
    assert(down_sock)
    down_sock:settimeouts(60000, 60000, 60000)
    return down_sock
end

function _M:new(up_host, up_port)
    return setmetatable({
        down_conn = nil,
        down_phase = 0, -- 0:初始连接阶段；1：认证阶段；2：命令阶段；3：自由通信阶段；
        up_conn = nil,
        up_host = up_host,
        up_port = up_port,
        up_conn_timeout = 60000,
        up_send_timeout = 60000,
        up_read_timeout = 60000,
        is_up_close = true,
        is_down_close = true,
        up_loop_thread = nil,
    }, mt)
end

function _M:connectup()
    self.up_conn = tcp_conn:new()
    local sock, err = self.up_conn:start(self.up_host, self.up_port)
    assert(sock)
    self.is_up_close = false
    ngx.log(ngx.DEBUG, "successfully connected to upstream!")
    return self.up_conn
end

function _M:send_to_up(o)
    if not self.up_conn or self.is_up_close then
        ngx.log(ngx.WARN, "upstream is closed")
        return nil, "upstream is closed"
    end
    local bytes, err = self.up_conn:send(o)
    if not bytes then
        ngx.log(ngx.ERR, "send_to_up failed to send ", err)
        return nil, err
    end
    return bytes, err
end

function _M:send_to_down(s)
    if not self.down_conn or self.is_down_close then
        ngx.log(ngx.WARN, "downstream is closed")
    end
    local bytes, err = self.down_conn:send(s)
    if not bytes then
        ngx.log(ngx.ERR, "send_to_down failed to send ", err)
        return
    end
end

function _M:down_loop()
    local proxy_req_cnt = 0
    while not self.is_down_close do
        -- 收消息
        
        if self.down_phase == 0 then
            -- 进入认证阶段
            self.down_phase = 1
            local raw, err = self.down_conn:receive(2)
            if not raw then
                ngx.log(ngx.ERR, "down_loop msg error ", err)
                self.is_down_close = true
                return
            end
            -- ngx.log(ngx.DEBUG, "------", raw, " ", str_len(raw))
            if str_len(raw) < 2 then
                ngx.log(ngx.ERR, "down_loop msg len error in auth phase")
                self.is_down_close = true
                return
            end
            local ver, methods_cnt = str_byte(raw, 1, 2)
            -- ngx.log(ngx.ERR, "------", ver, " ", method_cnt)
            if not ver or ver ~= 0x05 then
                ngx.log(ngx.ERR, "down_loop msg ver error in auth phase")
                self.is_down_close = true
                return
            end
            raw, err = self.down_conn:receive(methods_cnt)
            if not raw then
                ngx.log(ngx.ERR, "down_loop msg methods error ", err)
                self.is_down_close = true
                return
            end
            self:send_to_down(str_char(0x05) .. str_char(0x00))
            self.down_phase = 2
            ngx.log(ngx.DEBUG, "------ auth ok")
        elseif self.down_phase == 2 then
            -- 进入命令阶段
            local raw, err = self.down_conn:receive(4)
            if not raw then
                ngx.log(ngx.ERR, "down_loop msg error ", err)
                self.is_down_close = true
                return
            end
            -- ngx.log(ngx.DEBUG, "------", raw, " ", str_len(raw))

            if str_len(raw) < 4 then
                ngx.log(ngx.ERR, "down_loop msg len error in cmd phase")
                self.is_down_close = true
                return
            end
            local ver, cmd, rsv, addr_type = str_byte(raw, 1, 4)
            -- ngx.log(ngx.ERR, "------", ver, " ", cmd, " ",rsv," ", addr_type)
            if not ver or ver ~= 0x05 then
                ngx.log(ngx.ERR, "down_loop msg ver error in cmd phase")
                self.is_down_close = true
                return
            end
            if cmd ~= 0x01 then
                ngx.log(ngx.ERR, "down_loop unsupported command error in cmd phase ", str_char(cmd), cmd)
                self.is_down_close = true
                return
            end
            local target_host = nil
            local target_port = 0
            if addr_type == 0x01 then
                -- IP
                raw, err = self.down_conn:receive(6)
                if not raw then
                    ngx.log(ngx.ERR, "down_loop ip error ", err)
                    self.is_down_close = true
                    return
                end
                -- ngx.log(ngx.DEBUG, "------ ip ", raw, " ", str_len(raw))
                local ip1, ip2, ip3, ip4 = str_byte(raw, 1, 4)
                target_host = ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4
                local port1, port2 = str_byte(raw, 5, 6)
                target_port = bor(lshift(port1, 8), port2)
            elseif addr_type == 0x03 then
                -- domain
                raw, err = self.down_conn:receive(1)
                if not raw then
                    ngx.log(ngx.ERR, "down_loop domain_len error ", err)
                    self.is_down_close = true
                    return
                end
                -- ngx.log(ngx.DEBUG, "------ domain ", raw, " ", str_len(raw))
                local domain_len = str_byte(raw)
                raw, err = self.down_conn:receive(domain_len + 2)
                if not raw then
                    ngx.log(ngx.ERR, "down_loop domain error ", err)
                    self.is_down_close = true
                    return
                end
                -- ngx.log(ngx.DEBUG, "------ domain ", raw, " ", str_len(raw))
                target_host = str_sub(raw, 1, domain_len)
                local port1, port2 = str_byte(raw, domain_len + 1, domain_len + 2)
                target_port = bor(lshift(port1, 8), port2)
            elseif addr_type == 0x04 then
                ngx.log(ngx.ERR, "down_loop unsupported IP V6 error in cmd phase ", str_char(addr_type))
                self.is_down_close = true
                return
            else
                ngx.log(ngx.ERR, "down_loop unsupported ADDRESS_TYPE error in cmd phase ", str_char(addr_type))
                self.is_down_close = true
                return
            end
            -- ngx.log(ngx.DEBUG, "------ target_host ", target_host, " target_port ", target_port)

            -- 包装消息发送到真正的代理服务
            local msg = {
                cmd = "connect",
                host = target_host,
                port = target_port,
            }
            local bytes, _ = self:send_to_up(msg)
            if not bytes then
                self:send_to_down(str_char(0x05) .. str_char(0x04) .. str_sub(raw, 3))
                self.is_down_close = true
                return
            end

            -- self:send_to_down(str_char(0x05) .. str_char(0x00) .. str_sub(raw, 3, 8) .. str_char(0x00) .. str_char(0x1A) .. str_char(0x0A))
            self:send_to_down(str_char(0x05) .. str_char(0x00) .. str_char(0x00) .. str_char(0x01) .. str_char(0x7f) .. str_char(0x00) .. str_char(0x00) .. str_char(0x01) .. str_char(0x1A) .. str_char(0x0A))
            ngx.log(ngx.DEBUG, "------ cmd phase ok ", target_host, " target_port ", target_port)
            self.down_phase = 3
        elseif self.down_phase == 3 then
            -- 自由通信阶段
            -- proxy_req_cnt = proxy_req_cnt + 1
            -- ::cmd_proxy_req::
            -- ngx.sleep(1)
            -- ngx.log(ngx.DEBUG, "------ cmd proxy proxy_req_cnt: ", proxy_req_cnt)
            local raw, err = self.down_conn:receiveany(102400)
            if not raw then
                -- ngx.log(ngx.ERR, "cmd proxy msg error ", err)
                self.is_down_close = true
                return
                -- goto cmd_proxy_req
            end
            -- ngx.log(ngx.DEBUG, "------ cmd proxy ", raw, " ", str_len(raw))
            local msg = {
                cmd = "proxy",
                payload = raw
            }
            -- ngx.log(ngx.DEBUG, "------  cmd proxy  ", raw)
            local bytes, _ = self:send_to_up(msg)
            if not bytes then
                self.is_down_close = true
                return
            end
            ngx.log(ngx.DEBUG, "------ cmd proxy end ")
        else
            ngx.log(ngx.ERR, "down_loop phase error ", self.is_down_close)
            self.is_down_close = true
            return
        end
    end
    self.is_down_close = true
    return
end

function _M:up_loop()
    ::continue::
    while not self.is_up_close do
        ngx.log(ngx.DEBUG, "------ up_loop recv")
        local msg, err = self.up_conn:recv()
        if err == "timeout" then
            ngx.log(ngx.DEBUG, "------ up_loop read timeout")
            goto continue
        end
        if not msg then
            ngx.log(ngx.ERR, "up_loop msg error ", err)
            self.is_up_close = true
            return
        end
        -- ngx.log(ngx.DEBUG, "------ up_loop msg ", encode_json(msg))
        if msg.cmd and msg.cmd == "proxy" then
            self:send_to_down(msg.payload)
        else
            ngx.log(ngx.ERR, "up_loop msg.cmd error ")
            self.is_up_close = true
            return
        end
    end
    self.is_down_close = true
end


function _M:start()
    self.down_conn = connectdown()
    self.is_down_close = false


    -- 连接到上游代理服务
    local upsock, _ = self:connectup()
    if not upsock then
        self.is_down_close = true
        return
    end
    self.is_down_close = false

    -- 启动上游协程
    self.up_loop_thread = ngx.thread.spawn(self.up_loop, self)

    -- 启动下游循环
    -- local ok, err = pcall(self.down_loop, self)
    -- if not ok then
    --     ngx.log(ngx.ERR, "down_loop error ", err)
    -- end
    self:down_loop()
    ngx.log(ngx.DEBUG, "------ sock5 gate down_loop end")

    self.is_down_close = true

    self.is_up_close = true
    if self.up_loop_thread then
        ngx.thread.kill(self.up_loop_thread)
    end

    -- 安全关闭连接
    self.down_conn:close()
    self.up_conn:close()

    ngx.log(ngx.DEBUG, "------ sock5 gate end")
end

return _M
