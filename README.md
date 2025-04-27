# Openice
Open eyes to the world.

## Prepares
Install [OpenResty](https://github.com/openresty/openresty).

## Config
Create "config.lua" in "src" directory.
The contents are as follows:
```
local _M = {}

-- remote address is valid in local mode.
_M.remote_host = "127.0.0.1"

-- remote port is valid in local mode.
_M.remote_port = 9998

-- key used for encrypt data.
_M.key = "your password"

return _M

```
Add the following content to "nginx.conf":
```
stream {
    lua_package_path '/pathtolua/src/?.lua;';

    # if local mode.
    server {
        listen 9997;
        #lua_code_cache off;
        content_by_lua_file ../src/local.lua;
    }

    # if remote mode.
    server {
        listen 9998;
        #lua_code_cache off;
        content_by_lua_file ../src/remote.lua;
    }
}

```

Enjoy it.



