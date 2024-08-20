//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <muduo/net/TcpServer.h>
#include "base/SocksResponse.h"
#include "base/ConnectionQueue.h"
#include "muduo/base/Logging.h"
#include "muduo/net/InetAddress.h"
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
public:
    SocksServer(muduo::net::EventLoop *loop, 
                const muduo::net::InetAddress &listenAddr,
                bool noAuth = false,
                bool useDynamicPassword = true,
                const std::string &username = "",  // is this ref valid?
                const std::string &password = "",  // is this ref valid?
                bool skipLocal = true,
                std::size_t connMaxNum = 163,
                std::size_t highMarkKB = 1024) : 
        server_(loop, listenAddr, "SocksServer"),
        loop_(loop), 
        tunnels_(connMaxNum),
        cq_(connMaxNum, connMaxNum * 2),
        tunnelPeekCount_(0),
        associationAddr_(),
        noAuth_(noAuth),
        useDynamicPassword_(useDynamicPassword),
        username_(username),
        password_(password),
        skipLocal_(skipLocal),
        highMarkKB_(highMarkKB)
    {
        using std::placeholders::_1;
        using std::placeholders::_2;
        using std::placeholders::_3;
        
        server_.setConnectionCallback(std::bind(&SocksServer::onConnection, this, _1));
        server_.setMessageCallback(std::bind(&SocksServer::onRequestStage, this, _1, _2, _3));
    }
    void setAssociationAddr(const muduo::net::InetAddress &addr) 
    {
        associationAddr_ = addr;
        LOG_WARN << server_.name() << " UDP Association address on " << associationAddr_.toIpPort();
    }
    bool isSkipLocal() const { return skipLocal_; }
    void start() 
    { 
        LOG_WARN << server_.name() << " start on " << server_.ipPort();
        server_.start(); 
    }
private:
    void onConnection(const muduo::net::TcpConnectionPtr &conn);
    void onRequestStage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void onAuthenticationStage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void onCommandStage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);

    static inline void shutdownSocksReq(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf)
    {
        SocksResponse rep;
        rep.initGeneralResponse('\x07');
        conn->send(rep.responseData(), rep.responseSize());
        buf->retrieveAll();
    }

    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;

    HashMap<int64_t, TunnelPtr> tunnels_;
    ConnectionQueue<int64_t> cq_;
    int tunnelPeekCount_;

    muduo::net::InetAddress associationAddr_;

    const bool noAuth_;
    const bool useDynamicPassword_;
    const std::string username_;
    const std::string password_;

    const bool skipLocal_;

    const std::size_t highMarkKB_;
};


#endif //SOCKS5_SOCKSSERVER_H
