//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include <muduo/net/EventLoop.h>
#include "EncodeServer.h"

using namespace muduo::net;
using namespace muduo;

int main(int argc, char *argv[])
{
    // Logger::setLogLevel(Logger::DEBUG);
    LOG_INFO << "main pid " << getpid();
    std::string ip;
    uint16_t port;
    if(argc > 2) {
        port = atoi(argv[2]);
        ip = argv[1];
    } else if(argc > 1) {
        port = atoi(argv[1]);
        ip = "0.0.0.0";
    } else {
        port = 2333;
        ip = "0.0.0.0";
    }
    EventLoop loop;
    InetAddress addr(ip, port);
    SocksServer socksServer(&loop, addr, SocksServer::DYNAMIC_PSWD);
    EncodeServer encodeServer(&loop, InetAddress(ip, 6011));
    socksServer.start();
    encodeServer.start();
    loop.loop();
}