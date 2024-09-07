//
// Created by clay on 22-10-13.
//

#ifndef PROXY_TUNNEL_H
#define PROXY_TUNNEL_H

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <functional>
#include <muduo/base/Logging.h>
#include <muduo/net/EventLoop.h>
#include <muduo/net/InetAddress.h>
#include <muduo/net/TcpClient.h>
#include <muduo/net/TcpServer.h>
#include "base/SocksUtils.h"
#include "muduo/net/Callbacks.h"

// only in tunnel can get response from destination
class Tunnel : public std::enable_shared_from_this<Tunnel>, muduo::noncopyable {
    static constexpr size_t K = 1024;
public:
    Tunnel(muduo::net::EventLoop *loop,
           const muduo::net::InetAddress &destination,
           const muduo::net::TcpConnectionPtr src_conn,
           size_t high_mark_kb = 1024)
    : loop_(loop), 
      client_(loop, destination, src_conn->name()),
      srcConn_(src_conn),
      highMarkKB_(high_mark_kb)
    {
        LOG_INFO << "Tunnel[" << client_.name() << "]"
                 << " " << src_conn->peerAddress().toIpPort()
                 << " <-> " << destination.toIpPort();
    }
    ~Tunnel()
    {
        LOG_INFO << "~Tunnel[" << client_.name() << "]";
        assert(!srcConn_ || !srcConn_->connected());  // lifetime restrict
        if (dstConn_ && dstConn_->connected()) {
            LOG_INFO << "Tunnel[" << client_.name() << "]"
                     << " actively shutdown dst " << dstConn_->peerAddress().toIpPort();
            dstConn_->shutdown();  // force or shutdown?
            // NOTE: to avoid weak cb
            dstConn_->setConnectionCallback(muduo::net::defaultConnectionCallback);
            dstConn_->setMessageCallback(muduo::net::defaultMessageCallback);
        }
    }

    void setup()
    {
        using std::placeholders::_1;
        using std::placeholders::_2;
        using std::placeholders::_3;

        // NOTE: it should be weak, because dst may survive (which will invoke cb) even if client_ die
        // NOTE: it can use this instead of weak_from_this, because I can reset cb in ~Tunnel and this problem originate from tunnel's lifetime
        client_.setConnectionCallback(std::bind(&Tunnel::onDstConnection, this, _1));
        client_.setMessageCallback(std::bind(&Tunnel::onDstMessage, this, _1, _2, _3));
        srcConn_->setHighWaterMarkCallback(
            std::bind(
                &Tunnel::onHighWaterMarkWeak, 
                weak_from_this(), 
                kServer, 
                _1, 
                _2
            ),
            highMarkKB_ * K
        );
    }

    void connect()
    {
        client_.connect();
    }

    void disconnect()
    {
        // how about not connected yet when source close actively?
        // it will invoke socksServer::onConnection and erase tunnel, also client_
        client_.disconnect();
    }

    void onEstablishedSrcMessage(
        const muduo::net::TcpConnectionPtr &conn,
        muduo::net::Buffer *buf,
        muduo::Timestamp time
    )  // recv from established src conn
    {
        assert(conn == srcConn_);
        if (dstConn_ && dstConn_->connected()) {
            LOG_INFO << "Tunnel[" << client_.name() << "] - "
                     << dstConn_->peerAddress().toIpPort() << " <- " << srcConn_->peerAddress().toIpPort()
                     << " " << buf->readableBytes() << " bytes";
            // FIXME: broken pipe here
            dstConn_->send(buf);
            assert(!buf->readableBytes());
        } else {
            // NOTE: data before establish will be transfered while dst connect
            LOG_INFO << "Tunnel[" << client_.name() << "] - "
                     << "dst not established with buf size " << buf->readableBytes()
                     << ", stop reading from src";
            assert(srcConn_->isReading());
            srcConn_->stopRead();  // wait for dst connection, in case buf explode
        }
    } 

private:
    void teardown()  // dst close actively
    {
        LOG_INFO << "Tunnel[" << client_.name() << "] - " << "teardown";
        if (srcConn_) {   // Q3: disconnect source conn actively when dest close first
            // srcConn_->setContext(boost::any());  // why it's necessary???
            /* forceClose for:
                1. trigger onConnection to release srcConn immediately then
                2. ~Tunnel as early as soon and save more fd
                3. simulate connection close
                4. it may fix the bug that dst close but src exist
             */
            /* shutdown for:
                1. dst data transfer completely
             */
            LOG_INFO << "Tunnel[" << client_.name() << "] - "
                     << "actively close src " << srcConn_->peerAddress().toIpPort();
            srcConn_->shutdown();
        }
        dstConn_.reset();  // tunnel may exist, even dst close actively, because shutdown will not invoke onConnection immediately
    }

    void onDstConnection(const muduo::net::TcpConnectionPtr &conn)   // destination connection
    {
        using std::placeholders::_1;
        using std::placeholders::_2;

        LOG_INFO_CONN << (conn->connected() ? "UP" : "DOWN");
        if(conn->connected()) { // destination connected
            conn->setTcpNoDelay(true);
            conn->setHighWaterMarkCallback(std::bind(&Tunnel::onHighWaterMarkWeak,
                                                         weak_from_this(), kClient, _1, _2), 
                             highMarkKB_ * K);
            // srcConn_->setContext(conn);  // why it's necessary??? dst lifetime is longer than src
            dstConn_ = conn;
            if (!srcConn_->isReading()) {
                LOG_INFO << "src start reading";
                srcConn_->startRead();  // Q1: when destination connected then start read source requests
            }
            if(srcConn_->inputBuffer()->readableBytes() > 0) {   // Q1: not yet connected to destination but got requests from source
                LOG_INFO << "src input buf reserve " << srcConn_->inputBuffer()->readableBytes();
                conn->send(srcConn_->inputBuffer()); // send requests from source to destination
            }
        } else {    // Q3: destination disconnected actively
            LOG_INFO_CONN << "destination close";
            teardown(); // disconnect source conn actively
        }
    }

    void onDstMessage(
        const muduo::net::TcpConnectionPtr &conn,
        muduo::net::Buffer *buf,
        muduo::Timestamp time
    )  // receive from destination
    {
        assert(conn == dstConn_);
        LOG_INFO << "Tunnel[" << client_.name() << "] - "
                 << dstConn_->peerAddress().toIpPort() << " -> " << srcConn_->peerAddress().toIpPort()
                 << " " << buf->readableBytes() << " bytes";
        assert(srcConn_->connected());
        srcConn_->send(buf); // send response from destination to source
    }

    enum ServerClient {
        kServer, kClient
    };

    void onHighWaterMark(ServerClient which,
                         const muduo::net::TcpConnectionPtr &conn,
                         size_t bytesToSent)
    {
        using std::placeholders::_1;

        LOG_INFO << "Tunnel-" << this << " "
                 << (which == kServer ? "server" : "client")
                 << " onHighWaterMark " << conn->peerAddress().toIpPort()
                 << " bytes " << bytesToSent;
        if(which == kServer) {  // source output buffer full
            if(srcConn_->outputBuffer()->readableBytes() > 0) {  // sent not yet
                dstConn_->stopRead();    // stop reading response from destination
                srcConn_->setWriteCompleteCallback(
                std::bind(
                    &Tunnel::onWriteCompleteWeak,
                        weak_from_this(),
                        kServer, 
                        _1
                    )
                );  // continue to send to source when write completely
            }
            // sent yet
        } else {    // destination output buffer full
            if(dstConn_->outputBuffer()->readableBytes() > 0) {
                srcConn_->stopRead();
                dstConn_->setWriteCompleteCallback(
                    std::bind(
                        &Tunnel::onWriteCompleteWeak,
                        weak_from_this(), 
                        kClient, 
                        _1
                    )
                );
            }
        }
    }
    static void onHighWaterMarkWeak(const std::weak_ptr<Tunnel> &wkTunnel,
                                    ServerClient which,
                                    const muduo::net::TcpConnectionPtr &conn,
                                    size_t bytesToSent)  // weak callback for when serverConn close but serverConn exist 
    {
        std::shared_ptr<Tunnel> tunnel = wkTunnel.lock();
        // src exist but tunnel may not exist, so it will toggle even if tunnel die
        // tunnel die, dst must be dead
        if(tunnel) {
            tunnel->onHighWaterMark(which, conn, bytesToSent);
        }
    }

    void onWriteComplete(ServerClient which, const muduo::net::TcpConnectionPtr &conn)  // continue to send
    {
        LOG_INFO << "Tunnel-" << this << " "
                 << (which == kServer ? "server" : "client")
                 << " onWriteComplete " << conn->peerAddress().toIpPort();
        if(which == kServer) {  // sent to destination(server) yet, source output buffer not full
            dstConn_->startRead();  // start to read from destination
            srcConn_->setWriteCompleteCallback(muduo::net::WriteCompleteCallback());  // default callback
        } else {
            srcConn_->startRead();
            dstConn_->setWriteCompleteCallback(muduo::net::WriteCompleteCallback());
        }
    }
    static void onWriteCompleteWeak(const std::weak_ptr<Tunnel> &wkTunnel,
                                    ServerClient which,
                                    const muduo::net::TcpConnectionPtr &conn)  // weak callback for what ?
    {
        // tunnel die, dst must be dead
        // dst die, src should close, it's not required to startRead
        std::shared_ptr<Tunnel> tunnel = wkTunnel.lock();
        if(tunnel) {
            tunnel->onWriteComplete(which, conn);
        }
    }

    muduo::net::EventLoop *loop_;
    muduo::net::TcpClient client_;
    muduo::net::TcpConnectionPtr  srcConn_;  // source
    muduo::net::TcpConnectionPtr dstConn_;   // destination
    size_t highMarkKB_;
};
typedef std::shared_ptr<Tunnel> TunnelPtr;

#endif //PROXY_TUNNEL_H
