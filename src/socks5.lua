local bit = require "bit"
local cjson = require "cjson.safe"

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

local function connect_frontend()
    local frontend_sock, err = ngx.req.socket(true)
    assert(frontend_sock)
    frontend_sock:settimeouts(60000, 60000, 60000)
    return frontend_sock
end

function _M:new()
    return setmetatable({
        frontend_sock = nil,
        frontend_phase = 0, -- 0:初始连接阶段；1：认证阶段；2：命令阶段；3：自由通信阶段；
        backend_sock = nil,
        backend_sock_timeout = 60000,
        backend_send_timeout = 60000,
        backend_read_timeout = 60000,
        is_backend_close = true,
        is_frontend_close = true,
        backend_loop_thread = nil,
    }, mt)
end

function _M:connect_backend(host, port)
    self.backend_sock = ngx.socket.tcp()
    ngx.log(ngx.DEBUG, "connect_backend start")
    local ok, err = self.backend_sock:connect(host, port)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect ", host, " : ", port, " ", err)
        return nil, err
    end
    self.backend_sock:settimeouts(self.backend_sock_timeout, self.backend_send_timeout, self.backend_read_timeout)
    self.is_backend_close = false
    ngx.log(ngx.DEBUG, "successfully connected to backendstream!")
    return self.backend_sock
end

function _M:send_to_backend(o)
    if not self.backend_sock or self.is_backend_close then
        ngx.log(ngx.WARN, "backendstream is closed")
        return nil, "backendstream is closed"
    end
    local bytes, err = self.backend_sock:send(o)
    if not bytes then
        ngx.log(ngx.ERR, "send_to_backend failed to send ", err)
        return nil, err
    end
    return bytes, err
end

function _M:send_to_frontend(s)
    if not self.frontend_sock or self.is_frontend_close then
        ngx.log(ngx.WARN, "frontendstream is closed")
    end
    local bytes, err = self.frontend_sock:send(s)
    if not bytes then
        ngx.log(ngx.ERR, "send_to_frontend failed to send ", err)
        return
    end
end

function _M:frontend_loop()
    -- local proxy_req_cnt = 0
    ngx.log(ngx.DEBUG, "frontend_loop start " .. encode_json(self.is_frontend_close))
    while not self.is_frontend_close do
        -- 收消息
        if self.frontend_phase == 0 then
            -- 进入认证阶段
            self.frontend_phase = 1
            local raw, err = self.frontend_sock:receive(2)
            if not raw then
                ngx.log(ngx.ERR, "frontend_loop msg error ", err)
                self.is_frontend_close = true
                return
            end
            if str_len(raw) < 2 then
                ngx.log(ngx.ERR, "frontend_loop msg len error in auth phase")
                self.is_frontend_close = true
                return
            end
            local ver, methods_cnt = str_byte(raw, 1, 2)
            if not ver or ver ~= 0x05 then
                ngx.log(ngx.ERR, "frontend_loop msg ver error in auth phase")
                self.is_frontend_close = true
                return
            end
            raw, err = self.frontend_sock:receive(methods_cnt)
            if not raw then
                ngx.log(ngx.ERR, "frontend_loop msg methods error ", err)
                self.is_frontend_close = true
                return
            end
            self:send_to_frontend(str_char(0x05) .. str_char(0x00))
            self.frontend_phase = 2
            ngx.log(ngx.DEBUG, "------ auth ok")
        elseif self.frontend_phase == 2 then
            -- 进入命令阶段
            ngx.log(ngx.DEBUG, "------ start cmd phase")
            local raw, err = self.frontend_sock:receive(4)
            if not raw then
                ngx.log(ngx.ERR, "frontend_loop msg error ", err)
                self.is_frontend_close = true
                return
            end

            if str_len(raw) < 4 then
                ngx.log(ngx.ERR, "frontend_loop msg len error in cmd phase")
                self.is_frontend_close = true
                return
            end
            local ver, cmd, rsv, addr_type = str_byte(raw, 1, 4)
            if not ver or ver ~= 0x05 then
                ngx.log(ngx.ERR, "frontend_loop msg ver error in cmd phase")
                self.is_frontend_close = true
                return
            end
            if cmd ~= 0x01 then
                ngx.log(ngx.ERR, "frontend_loop unsupported command error in cmd phase ", str_char(cmd))
                self.is_frontend_close = true
                return
            end
            local target_host = nil
            local target_port = 0
            if addr_type == 0x01 then
                -- IP
                raw, err = self.frontend_sock:receive(6)
                if not raw then
                    ngx.log(ngx.ERR, "frontend_loop ip error ", err)
                    self.is_frontend_close = true
                    return
                end
                local ip1, ip2, ip3, ip4 = str_byte(raw, 1, 4)
                target_host = ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4
                local port1, port2 = str_byte(raw, 5, 6)
                target_port = bor(lshift(port1, 8), port2)
            elseif addr_type == 0x03 then
                -- domain
                raw, err = self.frontend_sock:receive(1)
                if not raw then
                    ngx.log(ngx.ERR, "frontend_loop domain_len error ", err)
                    self.is_frontend_close = true
                    return
                end
                local domain_len = str_byte(raw)
                raw, err = self.frontend_sock:receive(domain_len + 2)
                if not raw then
                    ngx.log(ngx.ERR, "frontend_loop domain error ", err)
                    self.is_frontend_close = true
                    return
                end
                ngx.log(ngx.DEBUG, "------ domain ", raw, " ", str_len(raw))
                target_host = str_sub(raw, 1, domain_len)
                local port1, port2 = str_byte(raw, domain_len + 1, domain_len + 2)
                target_port = bor(lshift(port1, 8), port2)
            elseif addr_type == 0x04 then
                ngx.log(ngx.ERR, "frontend_loop unsupported IP V6 error in cmd phase ", str_char(addr_type))
                self.is_frontend_close = true
                return
            else
                ngx.log(ngx.ERR, "frontend_loop unsupported ADDRESS_TYPE error in cmd phase ", str_char(addr_type))
                self.is_frontend_close = true
                return
            end
            ngx.log(ngx.DEBUG, "------ target_host ", target_host, " target_port ", target_port)

            -- 包装消息发送到真正的代理服务
            local sock, _ = self:connect_backend(target_host, target_port)
            if not sock then
                self:send_to_frontend(str_char(0x05) .. str_char(0x04) .. str_sub(raw, 3))
                self.is_frontend_close = true
                return
            end
            -- 启动上游协程
            self.backend_loop_thread = ngx.thread.spawn(self.backend_loop, self)

            ngx.log(ngx.DEBUG, "------ connect backend ok ")

            -- self:send_to_frontend(str_char(0x05) .. str_char(0x00) .. str_sub(raw, 3, 8) .. str_char(0x00) .. str_char(0x1A) .. str_char(0x0A))
            self:send_to_frontend(str_char(0x05) ..
                str_char(0x00) ..
                str_char(0x00) ..
                str_char(0x01) ..
                str_char(0x7f) .. str_char(0x00) .. str_char(0x00) .. str_char(0x01) .. str_char(0x1A) .. str_char(0x0A))
            ngx.log(ngx.DEBUG, "------ cmd phase ok ", target_host, " target_port ", target_port)
            self.frontend_phase = 3
        elseif self.frontend_phase == 3 then
            -- 自由通信阶段
            local raw, err = self.frontend_sock:receiveany(102400)
            if not raw then
                -- ngx.log(ngx.ERR, "cmd proxy msg error ", err)
                self.is_frontend_close = true
                return
            end
            local bytes, _ = self:send_to_backend(raw)
            if not bytes then
                self.is_frontend_close = true
                return
            end
            ngx.log(ngx.DEBUG, "------ cmd proxy end ")
        else
            ngx.log(ngx.ERR, "frontend_loop phase error ", self.is_frontend_close)
            self.is_frontend_close = true
            return
        end
    end
    self.is_frontend_close = true
end

function _M:backend_loop()
    ngx.log(ngx.DEBUG, "backend_loop start " .. encode_json(self.is_backend_close))

    ::continue::
    while not self.is_backend_close do
        ngx.log(ngx.DEBUG, "------ backend_loop recv 111")
        local msg, err = self.backend_sock:receiveany(10 * 1024)
        if err == "timeout" then
            ngx.log(ngx.DEBUG, "------ backend_loop read timeout")
            goto continue
        end
        if not msg then
            ngx.log(ngx.ERR, "backend_loop msg error ", err)
            self.is_backend_close = true
            return
        end
        ngx.log(ngx.DEBUG, "------ backend_loop recv 222 ")
        self:send_to_frontend(msg)
    end
    self.is_frontend_close = true
    ngx.log(ngx.DEBUG, "------ backend_loop end ")
end

function _M:start()
    self.frontend_sock = connect_frontend()
    self.is_frontend_close = false

    self:frontend_loop()
    ngx.log(ngx.DEBUG, "------ sock5 server frontend_loop end")

    self.is_frontend_close = true

    self.is_backend_close = true
    if self.backend_loop_thread then
        ngx.thread.kill(self.backend_loop_thread)
    end

    -- 安全关闭连接
    -- local ok, err = self.frontend_sock:close()
    self.backend_sock:close()

    ngx.log(ngx.DEBUG, "------ sock5 server end")
end

return _M
