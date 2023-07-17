#include "Utils.h"
#include "MD5Encode.h"
#include <cassert>
#include <cstdio>
#include <map>
#include <string>
#include <ctime>
#include <muduo/base/Timestamp.h>

const char *getUsername()
{
    static constexpr char name[] = "koishi";
    return name;
}

std::string genPassword(const std::string &raw) 
{
    std::string res{genMD5(raw)};
    for(int i = 0; i < res.size(); ++i) {
        if(i % 3) {
            res[i] ^= 64;
        }
        if(!(i % 4) && res[i] <= 'z' && res[i] >= 'a') {
            res[i] ^= 32;
        }
    }
    return res;
}

std::string getGeneralPassword()
{
    time_t t;
    time(&t);
    auto one_week = 24 * 3600 * 7;
    t = t / one_week * one_week;
    static time_t ps_time{0};
    static std::string pswd;
    if(ps_time == t) {
        return pswd;
    }
    ps_time = t;
    pswd = genPassword("komeiji" + std::to_string(t) + getUsername());
    return pswd;
}

std::string genMD5(const std::string &raw) 
{
    Md5Encode encode;
    std::string rps = encode.Encode(raw);
    return rps;
}

bool authenticate(const std::string &user, const std::string &pswd)
{
    auto vu = getUsername();
    auto vps = getGeneralPassword();
    // printf("valid user: %s, valid password: %s\n", vu, vps.c_str());
    return vu == user && pswd == vps;
}