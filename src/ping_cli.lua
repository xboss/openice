local sock = ngx.socket.tcp()
assert(sock)
sock:settimeouts(60000, 60000, 60000)
local host = "185.149.23.225"
local port = 9997
local ok, err = sock:connect(host, port)
if not ok then
    print("failed to connect ", host, " : ", port, " ", err)
    return nil, err
end
print("connect to ", host, " ", port, " ok");

local running = true;

local function send_ping()
    local bytes, err, now
    while running do
        now = ngx.now() * 1000
        bytes, err = sock:send(now .. "")
        if not bytes then
            print("send failed ", err)
            break
        end
        -- print("send:", now)
        ngx.sleep(0.01)
    end
end

local send_thread = ngx.thread.spawn(send_ping)
print("start ping thread ok")

local sum = 0
local cnt = 0
local avg = 0
local raw, err
local now, rtt
while running do
    raw, err = sock:receive(13)
    if not raw then
        print("receive msg error ", err)
        break
    end

    now = ngx.now() * 1000
    rtt = now - tonumber(raw)
    sum = sum + rtt
    cnt = cnt + 1

    if cnt > 0 then
        avg = sum / cnt
    end
    print("rtt:", rtt, " avg:", avg);
end

ngx.thread.kill(send_thread)
print("end ping ")
