//
// Created by clay on 22-10-13.
//

#ifndef PROXY_TUNNEL_H
#define PROXY_TUNNEL_H

#define NOT_OUTPUT

#include <muduo/base/Logging.h>
#include <muduo/net/EventLoop.h>
#include <muduo/net/InetAddress.h>
#include <muduo/net/TcpClient.h>
#include <muduo/net/TcpServer.h>

#include <algorithm>

// only in tunnel can get response from destination
class Tunnel : public std::enable_shared_from_this<Tunnel>, muduo::noncopyable {
static constexpr size_t kHighMark = 1024 * 1024;
public:
    Tunnel(muduo::net::EventLoop *loop,
           const muduo::net::InetAddress &destination,
           const muduo::net::TcpConnectionPtr src_conn)
    : client_(loop, destination, src_conn->name()),
      serverConn_(src_conn), had_connected_(false)
    {
        LOG_INFO << "Tunnel-" << this << " " << src_conn->peerAddress().toIpPort()
                 << " <-> " << destination.toIpPort();
    }
    ~Tunnel()
    {
        LOG_INFO << "~Tunnel-" << this;
    }

    void setup()
    {
        using std::placeholders::_1;
        using std::placeholders::_2;
        using std::placeholders::_3;
        // FIXME: shared_from_this result in ~tunnel failed
        client_.setConnectionCallback(std::bind(&Tunnel::onClientConnection/* destination connection */,
                                                shared_from_this(), _1));
        client_.setMessageCallback(std::bind(&Tunnel::onClientMessage,
                                             shared_from_this(), _1, _2, _3));
        serverConn_->setHighWaterMarkCallback(std::bind(&Tunnel::onHighWaterMarkWeak,
                                                        std::weak_ptr<Tunnel>(shared_from_this()), kServer, _1, _2),
                                              kHighMark);
    }

    void connect()
    {
        client_.connect();
    }

    void disconnect()
    {
        // how about not connected yet when source close actively?
        if(!hadConnected()) {
            LOG_WARN << "Tunnel-"<< this <<" never connected yet";
            client_.setConnectionCallback(muduo::net::defaultConnectionCallback);
            client_.setMessageCallback(muduo::net::defaultMessageCallback);
        } 
        client_.disconnect();
    }

    bool hadConnected() const 
    {
        return had_connected_;
    }

private:
    void teardown() // src or dest close first
    {
        client_.setConnectionCallback(muduo::net::defaultConnectionCallback);
        client_.setMessageCallback(muduo::net::defaultMessageCallback);
        if(serverConn_) {   // Q3: disconnect source conn actively when dest close first
            serverConn_->setContext(boost::any());  // Q2 ?
            serverConn_->shutdown();    // how about close source directly ?
        }
        clientConn_.reset();    // ~clientConn_ in advance to prevent ~tunnel fail
    }

    void onClientConnection(const muduo::net::TcpConnectionPtr &conn)   // destination connection
    {
        using std::placeholders::_1;
        using std::placeholders::_2;

        LOG_DEBUG << (conn->connected() ? "UP" : "DOWN");
        if(conn->connected()) { // destination connected
            conn->setTcpNoDelay(true);
            conn->setHighWaterMarkCallback(std::bind(&Tunnel::onHighWaterMarkWeak,
                                                     std::weak_ptr<Tunnel>(shared_from_this()), kClient, _1, _2),
                                           kHighMark);
            serverConn_->setContext(conn);  // Q2: record conn to match its client_ ? how about return conn to src 
            serverConn_->startRead();       // Q1: when destination connected then start read source requests
            clientConn_ = conn;             // destination conn
            if(serverConn_->inputBuffer()->readableBytes() > 0) {   // Q1: not yet connected to destination but got requests from source
                conn->send(serverConn_->inputBuffer()); // send requests from source to destination
            }
            had_connected_ = true;
        } else {    // Q3: destination disconnected actively
            LOG_INFO << "Tunnel-" << this << " - destination close";
            teardown(); // disconnect source conn actively
        }
    }

    void onClientMessage(const muduo::net::TcpConnectionPtr &conn,
                         muduo::net::Buffer *buf,
                         muduo::Timestamp time)  // received from destination
    {
        LOG_DEBUG << conn->name() << " " << buf->readableBytes();
        if(serverConn_) {
            LOG_DEBUG << conn->name() << " - response to source";
            serverConn_->send(buf); // send response from destination to source
        } else {    // source died
            buf->retrieveAll(); // discard all received data
            abort();
        }
    }

    enum ServerClient {
        kServer, kClient
    };

    void onHighWaterMark(ServerClient which,
                         const muduo::net::TcpConnectionPtr &conn,
                         size_t bytesToSent)
    {
        using std::placeholders::_1;

        LOG_INFO << "Tunnel-"<< this
                 << (which == kServer ? "server" : "client")
                 << " onHighWaterMark " << conn->name()
                 << " bytes " << bytesToSent;
        if(which == kServer) {  // source output buffer full
            if(serverConn_->outputBuffer()->readableBytes() > 0) {  // sent not yet
                clientConn_->stopRead();    // stop reading response from destination
                serverConn_->setWriteCompleteCallback(std::bind(&Tunnel::onWriteCompleteWeak,
                                                                std::weak_ptr<Tunnel>(shared_from_this()),
                                                                        kServer, _1));  // continue to send to source when write completely
            }
            // sent yet
        } else {    // destination output buffer full
            if(clientConn_->outputBuffer()->readableBytes() > 0) {
                serverConn_->stopRead();
                clientConn_->setWriteCompleteCallback(std::bind(&Tunnel::onWriteCompleteWeak,
                                                                std::weak_ptr<Tunnel>(shared_from_this()), kClient, _1));
            }
        }
    }
    static void onHighWaterMarkWeak(const std::weak_ptr<Tunnel> &wkTunnel,
                                    ServerClient which,
                                    const muduo::net::TcpConnectionPtr &conn,
                                    size_t bytesToSent) // weak callback for what ?
    {
        std::shared_ptr<Tunnel> tunnel = wkTunnel.lock();
        if(tunnel) {
            tunnel->onHighWaterMark(which, conn, bytesToSent);
        }
    }

    void onWriteComplete(ServerClient which, const muduo::net::TcpConnectionPtr &conn)  // continue to send
    {
        LOG_INFO << "Tunnel-"<< this 
                 << (which == kServer ? "server" : "client")
                 << " onWriteComplete " << conn->name();
        if(which == kServer) {  // sent to destination(server) yet, source output buffer not full
            clientConn_->startRead();   // start to read from destination
            serverConn_->setWriteCompleteCallback(muduo::net::WriteCompleteCallback()); // default callback
        } else {
            serverConn_->startRead();
            clientConn_->setWriteCompleteCallback(muduo::net::WriteCompleteCallback());
        }
    }
    static void onWriteCompleteWeak(const std::weak_ptr<Tunnel> &wkTunnel,
                                    ServerClient which,
                                    const muduo::net::TcpConnectionPtr &conn)   // weak callback for what ?
    {
        std::shared_ptr<Tunnel> tunnel = wkTunnel.lock();
        if(tunnel) {
            tunnel->onWriteComplete(which, conn);
        }
    }

    muduo::net::TcpClient client_;
    muduo::net::TcpConnectionPtr  serverConn_;  // source
    muduo::net::TcpConnectionPtr clientConn_;   // destination
    bool had_connected_;
};
typedef std::shared_ptr<Tunnel> TunnelPtr;

#endif //PROXY_TUNNEL_H
