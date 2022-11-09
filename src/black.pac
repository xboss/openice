function FindProxyForURL(url, host) {
    if (isInNet(host, "192.168.1.0", "255.255.255.0")
        || isInNet(host, "192.168.0.0", "255.255.0.0")
        || isInNet(host, "127.0.0.0", "255.255.255.0")
        || shExpMatch(host, "*.local")
        || shExpMatch(host, "*.cn")

        || shExpMatch(host, "*.163.com")
        || shExpMatch(host, "*.126.net")
        || shExpMatch(host, "*.alicdn.com")
        || shExpMatch(host, "*.baidu.com")
        || shExpMatch(host, "*.baidustatic.com")
        || shExpMatch(host, "*.bdimg.com")
        || shExpMatch(host, "*.bdstatic.com")
        || shExpMatch(host, "*.biliapi.net")
        || shExpMatch(host, "*.bilibili.com")
        || shExpMatch(host, "*.bilivideo.com")
        || shExpMatch(host, "*.cnblogs.com")
        || shExpMatch(host, "*.csdn.net")
        || shExpMatch(host, "*.lencr.org")
        || shExpMatch(host, "*.mozilla.com")
        || shExpMatch(host, "*.mozilla.org")
        || shExpMatch(host, "*.qq.com")
        || shExpMatch(host, "*.tingyun.com")
        || shExpMatch(host, "*.toutiao.com")
        || shExpMatch(host, "*.vzuu.com")
        || shExpMatch(host, "*.zhihu.com")
        || shExpMatch(host, "*.zhimg.com")

    ) {
        return "DIRECT";
    }

    return "SOCKS5 127.0.0.1:1111";
}