//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <muduo/net/TcpServer.h>
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
public:
    enum ValidationMode {
        NONE, PSWD, DYNAMIC_PSWD, WHITE_LIST
    };
    SocksServer(muduo::net::EventLoop *loop, const muduo::net::InetAddress &listenAddr, ValidationMode validate_mode=NONE)
        : server_(loop, listenAddr, "SocksServer"), loop_(loop), validate_mode_(validate_mode)
    {
        server_.setConnectionCallback([this] (const auto &conn) {
            onConnection(conn);
        });
        server_.setMessageCallback([this] (const auto &conn, auto *buf, auto time) {
            onMessage(conn, buf, time);
        });
    }
    void start() { server_.start(); }
    void onConnection(const muduo::net::TcpConnectionPtr &conn);
    void onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp);
private:
    enum Status {
        WREQ, WVLDT, WCMD, ESTABL
    };
    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;
    std::map<std::string, TunnelPtr> tunnels_;
    std::map<std::string, Status> status_;
    ValidationMode validate_mode_;

    void handleWREQ(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleWVLDT(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleWCMD(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleESTABL(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
};


#endif //SOCKS5_SOCKSSERVER_H
