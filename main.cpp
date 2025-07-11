//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <muduo/net/EventLoop.h>
#include <stdexcept>
#include <string>
#include "EncodeServer.h"
#include "UdpAssociate.h"
#include "muduo/base/Logging.h"
#include "cdns/Resolver.h"
#include "muduo/net/InetAddress.h"
#include <nlohmann/json.hpp>
#include <string_view>

using namespace muduo::net;
using namespace muduo;
using json = nlohmann::json;

inline Logger::LogLevel parseStringLevel(std::string_view level)
{
    for (auto i : level) {
        i |= (2 << 4);
    }
    if (level == "trace") return Logger::TRACE;
    if (level == "debug") return Logger::DEBUG;
    if (level == "info") return Logger::INFO;
    if (level == "warn") return Logger::WARN;
    if (level == "error") return Logger::ERROR;
    if (level == "fatal") return Logger::FATAL;
    throw std::runtime_error("invalid logLevel");
}

void updateJsonConfig(json &j1, const json &j2)
{
    for (auto &i : j1.items()) {
        auto key = i.key();
        if (!j2.count(key)) {
            continue;
        }
        if (!j1[key].is_object()) {
            j1[key] = j2[key];
        } else {
            updateJsonConfig(j1[key], j2[key]);
        }
    }
}

constexpr char defautConfig[] = 
R"({
    "logLevel": "warn",
    "encodeServer": {
        "enable": true,
        "port": 6011
    },
    "socksServer": {
        "enable": true,
        "port": 2333,
        "authentication": {
            "noAuth": false,
            "useDynamicPassword": true,
            "username": "",
            "password": ""
        },
        "udpAssociation": {
            "enable": true,
            "hostname": "localhost",
            "port": 11451
        },
        "highWaterMark": 1024,
        "maxConnNum": 163,
        "ignoreLocal": true
    }
})";
constexpr char configPath[] = "config.json";

int main(int argc, char *argv[])
{
    json config = json::parse(defautConfig);
    {
        char buf[1024];
        auto fp = fopen(configPath, "r");
        if (fp) {
            std::string data;
            std::size_t sz;
            do {
                sz = fread(buf, 1, sizeof(buf), fp);
                data.append(buf, sz);
            } while (sz > 0);
            fclose(fp);
            fp = nullptr;
            json tempConfig = json::parse(data);
            if (!tempConfig.empty()) {
                updateJsonConfig(config, tempConfig);
            }
        } else {
            auto fp = fopen(configPath, "w");
            if (fp) {
                fwrite(defautConfig, 1, strlen(defautConfig), fp);
                fclose(fp);
                fp = nullptr;
            }
        }
    }
    
    Logger::setLogLevel(parseStringLevel(config["logLevel"].get<std::string>()));
    EventLoop loop;
    
    std::unique_ptr<EncodeServer> encodeServer = nullptr;
    json encodeConfig = config["encodeServer"];
    if (encodeConfig["enable"]) {
        InetAddress encodeAddr(encodeConfig["port"].get<uint16_t>());
        encodeServer = std::make_unique<EncodeServer>(&loop, encodeAddr);
    }
    
    std::unique_ptr<SocksServer> socksServer = nullptr;
    std::unique_ptr<UdpAssociation> udpAssociation = nullptr;
    std::unique_ptr<cdns::Resolver> resolver = nullptr;
    json socksConfig = config["socksServer"];
    if (socksConfig["enable"]) {
        InetAddress socksAddr(socksConfig["port"].get<uint16_t>());
        socksServer = std::make_unique<SocksServer>(&loop, 
                                                    socksAddr,
                                                    socksConfig["authentication"]["noAuth"],
                                                    socksConfig["authentication"]["useDynamicPassword"],
                                                    socksConfig["authentication"]["username"],
                                                    socksConfig["authentication"]["password"],
                                                    socksConfig["ignoreLocal"],
                                                    socksConfig["maxConnNum"],
                                                    socksConfig["highWaterMark"]);
        json assoConfig = socksConfig["udpAssociation"];
        if (assoConfig["enable"]) {
            InetAddress assoAddr(assoConfig["port"].get<uint16_t>());
            udpAssociation = std::make_unique<UdpAssociation>(&loop, assoAddr);
            resolver = std::make_unique<cdns::Resolver>(&loop);
            resolver->resolve(assoConfig["hostname"].get<std::string>(), [assoAddr, &socksServer](const InetAddress &association_addr) {
                socksServer->setAssociationAddr({ association_addr.toIp(), assoAddr.port() });
            });
        }
    }
    if (encodeServer)
        encodeServer->start();
    if (socksServer)
        socksServer->start();
    
    LOG_WARN << "loop-" << &loop << " start";
    loop.loop();
}
