//
// Created by clay on 12/17/22.
//

#ifndef SOCKS5_ENCODESERVER_H
#define SOCKS5_ENCODESERVER_H


#include <muduo/net/TcpServer.h>

class EncodeServer : muduo::noncopyable {
public:
    EncodeServer(muduo::net::EventLoop *loop, const muduo::net::InetAddress &listenAddr)
            : server_(loop, listenAddr, "EncodeServer"), loop_(loop)
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
    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;
};


#endif //SOCKS5_ENCODESERVER_H
