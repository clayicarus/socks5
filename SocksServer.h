//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

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
    void setAssociationAddr(const muduo::net::InetAddress &addr) 
    {
        association_addr_ = addr;
        LOG_WARN << server_.name() << " UDP Association address on " << association_addr_.toIpPort();
    }
    bool isSkipLocal() const { return skipLocal_; }
    void skipLocal(bool skip=true) { skipLocal_ = skip; }
    void start() 
    { 
        LOG_WARN << server_.name() << " start on " << server_.ipPort();
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
    muduo::net::InetAddress association_addr_;
    bool skipLocal_;
};


#endif //SOCKS5_SOCKSSERVER_H
