//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <muduo/net/TcpServer.h>
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
public:
    SocksServer(muduo::net::EventLoop *loop, const muduo::net::InetAddress &listenAddr)
        : server_(loop, listenAddr, "SocksServer"), loop_(loop)
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
    static bool isInList(const std::string &ip, const std::string& file);

    enum Status {
        WREQ, WVLDT, WCMD, ESTABL
    };
    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;
    std::map<std::string, TunnelPtr> tunnels;
    std::map<std::string, Status> status_;
};


#endif //SOCKS5_SOCKSSERVER_H
