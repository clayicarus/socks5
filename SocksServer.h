//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <cstdint>
#include <map>
#include <muduo/net/TcpServer.h>
#include <string>
#include "muduo/base/Logging.h"
#include "muduo/cdns/Resolver.h"
#include "muduo/net/InetAddress.h"
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
public:
    SocksServer(muduo::net::EventLoop *loop, const muduo::net::InetAddress &listenAddr)
        : server_(loop, listenAddr, "SocksServer"), loop_(loop), resolver_(loop)
    {
        server_.setConnectionCallback([this] (const auto &conn) {
            onConnection(conn);
        });
        server_.setMessageCallback([this] (const auto &conn, auto *buf, auto time) {
            onMessage(conn, buf, time);
        });
    }
    void setAssociationAddr(const std::string &name, uint16_t port) 
    {
        LOG_INFO << "Association address " << name << ":" << port;
        associationName_ = name;
        associationPort_ = port;
    }
    void start() 
    { 
        LOG_INFO << "SOCKS5 server start on " << server_.ipPort();
        server_.start(); 
    }
private:
    void onConnection(const muduo::net::TcpConnectionPtr &conn);
    void onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp);
    void handleWREQ(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleWVLDT(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleWCMD(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleESTABL(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void onResolved(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf,
                    const muduo::net::InetAddress &addr);

    enum Status {
        WREQ, WVLDT, WCMD, RESOLVING, ESTABL
    };
    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;
    cdns::Resolver resolver_;
    std::map<std::string, TunnelPtr> tunnels_;
    std::map<std::string, Status> status_;

    std::string associationName_;
    uint16_t associationPort_;
};


#endif //SOCKS5_SOCKSSERVER_H
