//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include <muduo/net/EventLoop.h>
using namespace muduo::net;
using namespace muduo;

int main(int argc, char *argv[])
{
    uint16_t port;
    if(argc > 1) {
        port = atoi(argv[1]);
    } else {
        port = 2333;
    }
    EventLoop loop;
    InetAddress addr(port);
    SocksServer socksServer(&loop, addr);
    socksServer.start();
    loop.loop();
}