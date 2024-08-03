//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <cstddef>
#include <cstdint>
#include <muduo/net/TcpServer.h>
#include "base/SocksResponse.h"
#include "base/ConnectionQueue.h"
#include "muduo/base/Logging.h"
#include "muduo/net/InetAddress.h"
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
    constexpr static std::size_t connMaxNum_ = 163;
public:
    SocksServer(muduo::net::EventLoop *loop, const muduo::net::InetAddress &listenAddr) : 
        server_(loop, listenAddr, "SocksServer"),
        loop_(loop), 
        tunnels_(connMaxNum_),
        status_(connMaxNum_),
        cq_(connMaxNum_, connMaxNum_ * 2),
        associationAddr_(),
        skipLocal_(true),
        tunnelMaxCount_(0),
        statusMaxCount_(0)
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
        associationAddr_ = addr;
        LOG_WARN << server_.name() << " UDP Association address on " << associationAddr_.toIpPort();
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
    HashMap<int64_t, TunnelPtr> tunnels_;
    HashMap<int64_t, Status> status_;
    ConnectionQueue<int64_t> cq_;
    muduo::net::InetAddress associationAddr_;
    bool skipLocal_;
    int tunnelMaxCount_;
    int statusMaxCount_;
};


#endif //SOCKS5_SOCKSSERVER_H
