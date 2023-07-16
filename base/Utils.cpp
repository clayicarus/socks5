#include "Utils.h"
#include "MD5Encode.h"
#include <cstdio>
#include <map>
#include <string>
#include <ctime>
#include <muduo/base/Timestamp.h>

std::string getUsername()
{
    const static std::string username = "koishi";
    return username;
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
    auto today = muduo::Timestamp::fromUnixTime(t);
    auto yest = muduo::Timestamp::fromUnixTime(t - 24 * 3600);
    auto res = genMD5("iiyo" + yest.toFormattedString().substr(0, 8));
    res += genMD5( "koishi" + today.toFormattedString(false).substr(0, 8));
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

std::string genMD5(const std::string &raw) 
{
    static std::map<std::string, std::string> raw_to_md5;
    auto it = raw_to_md5.find(raw);
    if(it != raw_to_md5.end()) {
        return it->second;
    }
    Md5Encode encode;
    std::string rps = encode.Encode(raw);
    raw_to_md5.emplace(raw, rps);
    return rps;
}
