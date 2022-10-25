//
// Created by clay on 10/3/22.
//

#include "Hostname.h"
#include <netdb.h>

bool Hostname::getHostByName()
{
    clearHostent();
    auto p_hostent = gethostbyname(name_.c_str());
    if(!p_hostent)
        return false;

    char *ptr;
    ptr = p_hostent->h_name;
    formalName_ = ptr;

    char **pptr;
    pptr = p_hostent->h_aliases;
    while(*pptr) {
        alias_.emplace_back(*pptr++);
    }

    auto ppin = reinterpret_cast<in_addr**>(p_hostent->h_addr_list);
    while(*ppin) {
        auto temp = **ppin++;
        address_.push_back(temp);
    }

    return true;
}

void Hostname::clearHostent()
{
    address_.clear();
    formalName_.clear();
    alias_.clear();
}