#ifndef SOCKS_UTILS_H
#define SOCKS_UTILS_H

#include "muduo/base/Logging.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#define LOG_DEBUG_CONN LOG_DEBUG << conn->name() << " - "
#define LOG_INFO_CONN LOG_INFO << conn->name() << " - "
#define LOG_WARN_CONN LOG_WARN << conn->name() << " - "
#define LOG_ERROR_CONN LOG_ERROR << conn->name() << " - "
#define LOG_FATAL_CONN LOG_FATAL << conn->name() << " - "

using SocksAddressParseCallback = std::function<void(const muduo::net::InetAddress &addr)>;
using SocksAddressParseFailedCallback = std::function<void()>;
void parseSocksToInetAddress(muduo::net::EventLoop *loop, const void *atyp, 
    SocksAddressParseCallback succeeded_cb, SocksAddressParseFailedCallback failed_cb);

enum class SocksAddressType : char { 
    INCOMPLETED = '\x00', IPv4 = '\x01', DOMAIN_NAME = '\x03', IPv6 = '\x04', INVALID = '\xff'
};
inline SocksAddressType testSocksAddressType(const void *atyp, size_t rcv_len)
{
    const char *p = static_cast<const char *>(atyp);
    switch (static_cast<SocksAddressType>(*p)) {
        case SocksAddressType::IPv4:    // ATYP: IPv4
            if (rcv_len < 4 + 4 + 2) return SocksAddressType::INCOMPLETED;
            return SocksAddressType::IPv4;
        case SocksAddressType::DOMAIN_NAME:    // ATYP: DOMAIN_NAME
            if (rcv_len < 4 + p[1] + 2) return SocksAddressType::INCOMPLETED;
            return SocksAddressType::DOMAIN_NAME;
        case SocksAddressType::IPv6:    // ATYP: IPv6
            if (rcv_len < 4 + 16 + 2) return SocksAddressType::INCOMPLETED;
            return SocksAddressType::IPv6;
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

inline std::string parseSocksDomainName(const void *addr)
{
    auto p = static_cast<const char *>(addr);
    const char hostname_len = *p++;
    std::string hostname(p, p + hostname_len);
    return hostname;
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

inline bool isLocalIP(const muduo::net::InetAddress& addr)
{
    std::string ip = addr.toIp();

    // IPV4时候判断是否为本机IP
    if (ip.find('.') != std::string::npos) {
        size_t pos = ip.find('.');
        std::string ip_prefix = ip.substr(0, pos);

        // 判断IPv4 地址是否属于常见的保留地址范围：
        // 1.如果 IP 地址的前缀部分为 "10"，则判定为本地地址；
        // 2.如果 IP 地址的前缀部分为 "172"，并且第一个点后的两个数字在 16 到 31 之间，则判定为本地地址。
        // 3.如果 IP 地址的前缀部分为 "192"，并且第一个点后的三个数字为 "168"，则判定为本地地址
        if (ip_prefix == "10" ||
            (ip_prefix == "172" && ip.substr(pos + 1, 2) >= "16" && ip.substr(pos + 1, 2) <= "31") ||
            (ip_prefix == "192" && ip.substr(pos + 1, 3) == "168")) {
            return true;
        }
    }

    // TODO 判断IPV6没写

    return false;
}

#endif  // SOCKS_UTILS_H
