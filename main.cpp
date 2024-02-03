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
#include "muduo/net/InetAddress.h"

using namespace muduo::net;
using namespace muduo;

int main(int argc, char *argv[])
{
    // Logger::setLogLevel(Logger::DEBUG);
    uint16_t socks_port { 2333 }, association_port { 11451 }, encoder_port { 6011 };
    std::string association_address { "192.168.0.105" };
    if (argc > 4) {
        socks_port = atoi(argv[1]);
        association_address = argv[2];
        association_port = atoi(argv[3]);
        encoder_port = atoi(argv[4]);
    } else if (argc > 3) {
        socks_port = atoi(argv[1]);
        association_address = argv[2];
        association_port = atoi(argv[3]);
    } else if (argc > 2) {
        printf("usage: socks5 [socks_port] [assosiation_addr] [association_port] [encoder_port]\n");
        exit(-1);
    } else if (argc > 1) {
        socks_port = atoi(argv[1]);
    }
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
