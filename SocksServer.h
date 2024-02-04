//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <cstdint>
#include <map>
#include <muduo/net/TcpServer.h>
#include <string>
#include "base/SocksResponse.h"
#include "muduo/base/Logging.h"
#include "muduo/net/InetAddress.h"
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
public:
    SocksServer(muduo::net::EventLoop *loop, const muduo::net::InetAddress &listenAddr)
        : server_(loop, listenAddr, "SocksServer"), loop_(loop), skipLocal_(true)
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
    bool isSkipLocal() const { return skipLocal_; }
    void skipLocal(bool skip=true) { skipLocal_ = skip; }
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

    static inline void shutdownSocksReq(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf)
    {
        SocksResponse rep;
        rep.initGeneralResponse('\x07');
        conn->send(rep.responseData(), rep.responseSize());
        buf->retrieveAll();
    }

    enum Status {
        WREQ, WVLDT, WCMD, ESTABL
    };
    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;
    std::map<std::string, TunnelPtr> tunnels_;
    std::map<std::string, Status> status_;

    std::string associationName_;
    uint16_t associationPort_;

    bool skipLocal_;
};


#endif //SOCKS5_SOCKSSERVER_H
