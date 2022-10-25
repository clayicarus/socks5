//
// Created by clay on 10/3/22.
//

#ifndef PROXY_HOSTNAME_H
#define PROXY_HOSTNAME_H

#include<string>
#include<vector>
#include <sys/socket.h>
#include <arpa/inet.h>

class Hostname {
public:
    Hostname(std::string &&name) : name_(name) {}
    Hostname(const std::string &name) : name_(name) {}
    bool getHostByName();
    std::string name() const { return name_; }
    const std::string& formalName() const { return formalName_; }
    const std::vector<in_addr>& address() const { return address_; }
    const std::vector<std::string>& alias() const { return alias_; }
private:
    void clearHostent();
    std::vector<in_addr> address_;
    std::string formalName_;
    std::vector<std::string> alias_;
    std::string name_;
};


#endif //PROXY_HOSTNAME_H
