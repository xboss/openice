function FindProxyForURL(url, host) {
    // if (isInNet(host, "192.168.1.0", "255.255.255.0")
    //     || isInNet(host, "192.168.0.0", "255.255.0.0")
    //     || isInNet(host, "127.0.0.0", "255.255.255.0")
    //     || shExpMatch(host, "*.local")
    //     || shExpMatch(host, "*.cn")
    //     || shExpMatch(host, "*.baidu.com")
    //     || shExpMatch(host, "*.zhihu.com")
    //     || shExpMatch(host, "*.csdn.net")

    // ) {
    //     return "DIRECT";
    // }

    return "SOCKS5 127.0.0.1:3331";
}