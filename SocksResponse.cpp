//
// Created by clay on 12/18/22.
//

#include <cstring>
#include "SocksResponse.h"

void SocksResponse::initSuccessResponse(const in_addr &ipv4_addr, uint16_t port)
{
    response_.assign("\x05");       // VER
    response_.push_back('\x00');    // REP
    response_.push_back('\x00');    // RSV
    response_.push_back('\x01');        // atyp ipv4
    char temp[sizeof ipv4_addr + sizeof port + 1];
    memcpy(temp, &ipv4_addr, sizeof ipv4_addr);
    memcpy(temp + sizeof ipv4_addr, &port, sizeof port);
    temp[sizeof ipv4_addr + sizeof port] = '\0';
    response_ += temp;
    valid_ = true;
}

void SocksResponse::initSuccessResponse(const std::string &domain_name, uint16_t port)
{
    response_.assign("\x05");       // VER
    response_.push_back('\x00');    // REP
    response_.push_back('\x00');    // RSV
    response_.push_back('\x03');        // atyp domain name
    char len = static_cast<char>(domain_name.size());   // ?
    response_.push_back(len);
    response_ += domain_name;
    char temp[sizeof port + 1];
    memcpy(temp, &port, sizeof port);
    temp[sizeof port] = '\0';
    response_ += temp;
    valid_ = true;
}

void SocksResponse::initFailedResponse(const in_addr &ipv4_addr, uint16_t port, char rep)
{
    response_.assign("\x05");   // VER
    response_.push_back(rep);   // REP
    response_.push_back('\x00');// RSV
    response_.push_back('\x01');// ATYP ipv4
    char temp[sizeof ipv4_addr + sizeof port + 1];
    memcpy(temp, &ipv4_addr, sizeof ipv4_addr);
    memcpy(temp + sizeof ipv4_addr, &port, sizeof port);
    temp[sizeof ipv4_addr + sizeof port] = '\0';
    response_ += temp;
    valid_ = true;
}

void SocksResponse::initFailedResponse(const std::string &domain_name, uint16_t port, char rep)
{
    response_.assign("\x05");   // VER
    response_.push_back(rep);   // REP
    response_.push_back('\x00');// RSV
    response_.push_back('\x03');// ATYP dn
    char len = static_cast<char>(domain_name.size());   // ?
    response_.push_back(len);
    response_ += domain_name;
    char temp[sizeof port + 1];
    memcpy(temp, &port, sizeof port);
    temp[sizeof port] = '\0';
    response_ += temp;
    valid_ = true;
}
