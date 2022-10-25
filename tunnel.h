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
           const muduo::net::InetAddress &serverAddr,
           const muduo::net::TcpConnectionPtr clientConn)
    : client_(loop, serverAddr/* destination is client */, clientConn->name()),
      serverConn_(clientConn)   // source conn
    {
        LOG_INFO << "Tunnel " << clientConn->peerAddress().toIpPort()
                 << " <-> " << serverAddr.toIpPort();
    }
    ~Tunnel()
    {
        LOG_INFO << "~Tunnel";
    }

    void setup()
    {
        using std::placeholders::_1;
        using std::placeholders::_2;
        using std::placeholders::_3;

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
        client_.disconnect();
    }

private:
    void teardown() // Q3: disconnect source conn actively
    {
        client_.setConnectionCallback(muduo::net::defaultConnectionCallback);
        client_.setMessageCallback(muduo::net::defaultMessageCallback);
        if(serverConn_) {
            serverConn_->setContext(boost::any());  // Q2 ?
            serverConn_->shutdown();    // how about close source directly ?
        }
        clientConn_.reset();    // free shared_ptr (~clientConn_)
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
            serverConn_->setContext(conn);  // Q2: record conn to match its client_ ?
            serverConn_->startRead();       // Q1: when destination connected then start read source requests
            clientConn_ = conn;             // destination conn
            if(serverConn_->inputBuffer()->readableBytes() > 0) {   // Q1: not yet connected to destination but got requests from source
                conn->send(serverConn_->inputBuffer()); // send requests from source to destination
            }
        } else {    // Q3: destination disconnected actively
            LOG_INFO << conn->name() << " - Source close passively";
            teardown(); // disconnect source conn actively
        }
    }

    void onClientMessage(const muduo::net::TcpConnectionPtr &conn,
                         muduo::net::Buffer *buf,
                         muduo::Timestamp time)  // received from destination
    {
        LOG_DEBUG << conn->name() << " " << buf->readableBytes();
        if(serverConn_) {
#ifndef NOT_OUTPUT
            muduo::string req_str; // FIXME: O(buf->readableBytes())
            std::for_each(buf->toStringPiece().begin(), buf->toStringPiece().end(), [&req_str](const auto &i){
                if(i >= ' ' && i < 127) {
                    req_str.push_back(i);
                } else {
                    char format_num[5]; // 0 x 0 0 \0
                    snprintf(format_num, sizeof format_num, "0x%02x", i);
                    req_str.append(muduo::string("\\") + format_num);
                }
            });
            fprintf(stderr, "%s : %s - Response\n* begin *\n%s\n* end *\n", time.toFormattedString().c_str(), conn->name().c_str(), req_str.c_str());
#endif  // NOT_OUTPUT
            LOG_DEBUG << conn->name() << " - Response to source";
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

        LOG_INFO << (which == kServer ? "server" : "client")
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
        LOG_INFO << (which == kServer ? "server" : "client")
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
    muduo::net::TcpConnectionPtr  serverConn_;
    muduo::net::TcpConnectionPtr clientConn_;
};
typedef std::shared_ptr<Tunnel> TunnelPtr;

#endif //PROXY_TUNNEL_H
