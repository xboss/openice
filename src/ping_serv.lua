local sock, err = ngx.req.socket(true)
assert(sock)
sock:settimeouts(60000, 60000, 60000)

while true do
    local raw
    raw, err = sock:receive(13)
    if not raw then
        ngx.log(ngx.ERR, "receive msg error ", err)
        return
    end

    ngx.log(ngx.INFO, "msg:", raw);

    local bytes
    bytes, err = sock:send(raw)
    if not bytes then
        ngx.log(ngx.ERR, "send failed ", err)
        return
    end
end
