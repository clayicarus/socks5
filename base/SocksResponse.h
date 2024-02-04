//
// Created by clay on 12/18/22.
//

#ifndef SOCKS5_SOCKSRESPONSE_H
#define SOCKS5_SOCKSRESPONSE_H

#include "SocksUtils.h"
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <string>

class SocksResponse {
public:
    SocksResponse()
        : response_(), valid_(false) {}
    void initSuccessResponse(const in_addr &ipv4_addr, uint16_t port_net_endian);
    void initSuccessResponse(const in6_addr &ipv6_addr, uint16_t port_net_endian)
    {
        // VER REP RSV ATYP ADDR PORT 4 + 16 + 2
        response_.assign({ '\x05', '\x00', '\x00', static_cast<char>(SocksAddressType::IPv6) });
        char temp[sizeof(in6_addr) + sizeof(uint16_t)];
        memcpy(temp, &ipv6_addr, sizeof(ipv6_addr));
        memcpy(temp + sizeof(in6_addr), &port_net_endian, sizeof(uint16_t));
        response_ += std::string(temp, temp + sizeof(temp));
        valid_ = true;
    }
    void initSuccessResponse(const std::string &domain_name, uint16_t port);
    void initFailedResponse(const in_addr &ipv4_addr, uint16_t port, char rep = '\x01');
    void initFailedResponse(const std::string &domain_name, uint16_t port, char rep = '\x01');
    void initGeneralResponse(char rep = '\x00');
    const void * responseData() const { return response_.c_str(); }
    std::string::size_type responseSize() const { return response_.size(); }
    bool isValid() const { return valid_; }
private:
    std::string response_;
    bool valid_;
};


#endif //SOCKS5_SOCKSRESPONSE_H
