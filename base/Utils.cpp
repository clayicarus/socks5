#include "Utils.h"
#include "MD5Encode.h"
#include <cstdio>
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
    static std::string old_raw;
    static std::string old_md5;
    if(raw == old_raw) {
        return old_md5;
    } 
    Md5Encode encode;
    std::string rps = encode.Encode(raw);
    old_md5 = rps;
    old_raw = raw;
    return rps;
}