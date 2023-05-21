//
// Created by clay on 12/18/22.
//

#ifndef SOCKS5_SOCKSRESPONSE_H
#define SOCKS5_SOCKSRESPONSE_H

#include <memory>
#include <netinet/in.h>
#include <string>

class SocksResponse {
public:
    SocksResponse()
        : response_(), valid_(false) {}
    void initSuccessResponse(const in_addr &ipv4_addr, uint16_t port);
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
