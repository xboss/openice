function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.google.com")
        || shExpMatch(host, "*.github.com")
        || shExpMatch(host, "*.youtube.com")

    ) {
        return "SOCKS5 127.0.0.1:1111";
    }
    return "DIRECT";

}