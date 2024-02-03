#ifndef SOCKS_UTILS_H
#define SOCKS_UTILS_H

#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

using SocksAddressParseCallback = std::function<void(const muduo::net::InetAddress &addr)>;
using SocksAddressParseFailedCallback = std::function<void()>;
void parseSocksToInetAddress(muduo::net::EventLoop *loop, const void *atyp, 
    SocksAddressParseCallback succeeded_cb, SocksAddressParseFailedCallback failed_cb);

enum class SocksAddressType : char { 
    INCOMPLETED = '\x00', IPv4 = '\x01', IPv6 = '\x03', DOMAIN_NAME = '\x04', INVALID = '\xff'
};
inline SocksAddressType testSocksAddressType(const void *atyp, size_t rcv_len)
{
    const char *p = static_cast<const char *>(atyp);
    switch (*p) {
        case '\x01':
        if (rcv_len < 4 + 4 + 2) return SocksAddressType::INCOMPLETED;
        return SocksAddressType::IPv4;
        case '\x03':
        if (rcv_len < 4 + 16 + 2) return SocksAddressType::INCOMPLETED;
        return SocksAddressType::IPv6;
        case '\x04':
        if (rcv_len < 4 + p[1] + 2) return SocksAddressType::INCOMPLETED;
        return SocksAddressType::DOMAIN_NAME;
        default:
        return SocksAddressType::INVALID;
    }
}

inline std::string parseSocksDomainNamePort(const void *addr)
{
    auto p = static_cast<const char *>(addr);
    const char hostname_len = *p++;
    const void *p_port = p + hostname_len;
    std::string hostname(p, p + hostname_len);
    auto port = htons(*static_cast<const uint16_t *>(p_port));
    return hostname + ":" + std::to_string(port);
}

inline muduo::net::InetAddress parseSocksIPv4Port(const void *addr)
{
    auto p = static_cast<const char *>(addr);
    const void *ip = p;
    const void *port = p + 4;
    sockaddr_in sock_addr {};
    muduo::memZero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = *static_cast<const uint32_t *>(ip);
    sock_addr.sin_port = *static_cast<const uint16_t *>(port);
    return muduo::net::InetAddress(sock_addr);
}

inline muduo::net::InetAddress parseSocksIPv6Port(const void *addr)
{
    auto p = static_cast<const char *>(addr);
    const void *ip6 = p;
    const void *port = p + 16;
    sockaddr_in6 sock_addr;
    muduo::memZero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin6_family = AF_INET6;
    std::copy(static_cast<const uint8_t *>(ip6), static_cast<const uint8_t *>(ip6) + 8, sock_addr.sin6_addr.s6_addr);
    sock_addr.sin6_port = *static_cast<const uint16_t *>(port);
    return muduo::net::InetAddress(sock_addr);
}

#endif  // SOCKS_UTILS_H
