//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include <cstdio>
#include <cstdlib>
#include <muduo/net/EventLoop.h>
#include <string>
#include "EncodeServer.h"
#include "UdpAssociate.h"
#include "muduo/base/Logging.h"
#include "muduo/net/InetAddress.h"

using namespace muduo::net;
using namespace muduo;

inline int parseStringLevel(std::string level)
{
    for (auto &i : level) {
        i |= (2 << 4);
    }
    if (level == "trace") return Logger::TRACE;
    if (level == "debug") return Logger::DEBUG;
    if (level == "info") return Logger::INFO;
    if (level == "warn") return Logger::WARN;
    if (level == "error") return Logger::ERROR;
    if (level == "fatal") return Logger::FATAL;
    return -1;
}

int main(int argc, char *argv[])
{
    int level { Logger::WARN };
    uint16_t socks_port { 2333 }, association_port { 11451 }, encoder_port { 6011 };
    std::string association_address { "0.0.0.0" };
    switch (argc) {
        default:
        printf("Usage: socks5 [log level] [assosiation_addr] [association_port] [socks_port] [encoder_port]\n");
        exit(-1);
        case 6:
        encoder_port = atoi(argv[5]);
        case 5:
        socks_port = atoi(argv[4]);
        case 4:
        association_port = atoi(argv[3]);
        case 3:
        association_address = argv[2];
        case 2:
        if (argv[1] == std::string("-h") || argv[1] == std::string("--help")) {
            printf("Usage: socks5 [log level] [assosiation_addr] [association_port] [socks_port] [encoder_port]\n");
            exit(-1);
        }
        level = parseStringLevel(argv[1]);
        if (level == -1) {
            printf("Invalid log level\n");
            exit(-1);
        }
        case 1:
        break;
    }
    Logger::setLogLevel(static_cast<Logger::LogLevel>(level));
    InetAddress socks_address(socks_port), encoder_address(encoder_port), udp_address(association_port);
    EventLoop loop;
    SocksServer socksServer(&loop, socks_address);
    EncodeServer encodeServer(&loop, encoder_address);
    UdpAssociation udpAssociation(&loop, udp_address);
    socksServer.setAssociationAddr(association_address, udp_address.port());
    socksServer.start();
    encodeServer.start();
    loop.loop();
}
