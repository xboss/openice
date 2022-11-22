# openice
A socks5 server based on OpenResty.

## 状态
实现基本的socks5协议，目前不具备账号鉴权的功能。

## 使用
安装且配置好[OpenResty](https://github.com/openresty/openresty),

启动：
```
nginx -p `pwd` -c `pwd`/conf/nginx.conf
```

停止：
```
nginx -p `pwd` -s stop
```

## 注意
* 主要用来调试网络，流量监控和桥接，务必不要用于科学上网。
