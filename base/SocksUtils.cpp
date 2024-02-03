#include "muduo/cdns/Resolver.h"
#include "SocksUtils.h"

void parseSocksToInetAddress(muduo::net::EventLoop *loop, const void *atyp, SocksAddressParseCallback succeeded_cb, SocksAddressParseFailedCallback failed_cb)
{
    static cdns::Resolver resolver(loop);
    auto p = static_cast<const char *>(atyp);
    char addr_type = *p++;  // now p is atyp + 1
    switch(addr_type) {
        case '\x01':     // ATYP: IPv4
        {
            const void *ip = p;
            const void *port = p + 4;
            sockaddr_in sock_addr {};
            muduo::memZero(&sock_addr, sizeof(sock_addr));
            sock_addr.sin_family = AF_INET;
            sock_addr.sin_addr.s_addr = *static_cast<const uint32_t *>(ip);
            sock_addr.sin_port = *static_cast<const uint16_t *>(port);
            succeeded_cb(muduo::net::InetAddress(sock_addr));
            return;
        }
        case '\x03':    // ATYP: hostname
        {
            const char hostname_len = *p++;
            const void *p_port = p + hostname_len;
            std::string hostname(p, p + hostname_len);
            auto port = htons(*static_cast<const uint16_t *>(p_port));
            if (!resolver.resolve(hostname, [succeeded_cb, port](const muduo::net::InetAddress &resolved_addr) {
                succeeded_cb(muduo::net::InetAddress(resolved_addr.toIp(), port));
            })) failed_cb();
            return;
        }
        case '\x04':    // ATYP: IPv6
        {
            const void *ip6 = p;
            const void *port = p + 16;
            sockaddr_in6 sock_addr;
            muduo::memZero(&sock_addr, sizeof(sock_addr));
            sock_addr.sin6_family = AF_INET6;
            std::copy(static_cast<const uint8_t *>(ip6), static_cast<const uint8_t *>(ip6) + 8, sock_addr.sin6_addr.s6_addr);
            sock_addr.sin6_port = *static_cast<const uint16_t *>(port);
            succeeded_cb(muduo::net::InetAddress(sock_addr));
            return;
        }
        default:
        failed_cb();
        return;
    }
}
