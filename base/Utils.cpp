#include "Utils.h"
#include "MD5Encode.h"
#include <cstdio>
#include <map>
#include <string>
#include <ctime>
#include <muduo/base/Timestamp.h>

std::string getUsername()
{
    const static std::string username = "Koishi Komeiji";
    return username;
}

std::string getPassword()
{
    auto tp = muduo::Timestamp::now();
    auto res = genMD5("iiyo" + tp.toFormattedString().substr(0, 8) + "koishi");
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
