//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include <muduo/base/Logging.h>
#include <muduo/net/InetAddress.h>
#include "Hostname.h"
#include "MD5Encode.h"
#include "SocksResponse.h"
#include <set>
using namespace muduo;
using namespace muduo::net;

void SocksServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_DEBUG << conn->name() << " " << conn->peerAddress().toIpPort()
             << (conn->connected() ? "UP" : "DOWN");
    if(conn->connected()) {
        conn->setTcpNoDelay(true);
        auto it = status_.find(conn->name());
        if(it == status_.end()) {
            status_[conn->name()] = WREQ;
        }
    } else {
        auto it = tunnels.find(conn->name());
        if(it != tunnels.end()) {
            it->second->disconnect();
            tunnels.erase(it);
        }
        auto is = status_.find(conn->name());
        if(is != status_.end()) {
            status_.erase(is);
        }
    }
}

void SocksServer::onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    auto it = status_.find(conn->name());
    if(it == status_.end()) {
        // corpse is speaking
        LOG_FATAL << conn->name() << " - onMessage but no status";
        abort();
    } else {
        auto status = it->second;
        switch(status) {
            case WREQ:
                handleWREQ(conn, buf, time);
                if(buf->readableBytes() == 0) {
                    break;
                }
            case WVLDT:
                handleWVLDT(conn, buf, time);
                if(buf->readableBytes() == 0) {
                    break;
                }
            case WCMD:
                handleWCMD(conn, buf, time);
                if(buf->readableBytes() == 0) {
                    break;
                }
            case ESTABL:
                handleESTABL(conn, buf, time);
            break;
        }
    }
}

void SocksServer::handleWREQ(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_INFO << conn->name() << " - onMessage status WREQ";
    auto it = status_.find(conn->name());
    constexpr size_t headLen = 2;
    if(buf->readableBytes() > headLen) {
        const char ver = buf->peek()[0];
        const char len = buf->peek()[1];
        if(ver != '\x05') {
            conn->forceClose();
        } else if(buf->readableBytes() >= headLen + len) {
            const char *mthd = buf->peek() + 2;
            std::set<uint8_t> clientMethods;
            for(int i = 0; i < len; ++i) {
                clientMethods.insert(mthd[i]);
            }
            buf->retrieve(headLen + len);   // read and retrieve !!
            if(clientMethods.find('\x02') != clientMethods.end()) {
                char response[] = "V\x02";
                response[0] = ver;
                conn->send(response, 2);
                conn->setContext(boost::any('\x02'));
                it->second = WVLDT;
            } else {
                char response[] = "V\xff";
                response[0] = ver;
                conn->send(response, 2);
                conn->shutdown();
                buf->retrieveAll();
            }
        }
    }
}

void SocksServer::handleWVLDT(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_INFO << conn->name() << " - onMessage status WVLDT";
    auto it = status_.find(conn->name());
    if(!conn->getContext().empty()) {
        const char method = boost::any_cast<char>(conn->getContext());
        conn->setContext(boost::any());
        switch(method) {
            case '\x02':    // PASSWORD
            {
                if(buf->readableBytes() > 2) {
                    const char ver = buf->peek()[0];
                    const char ulen = buf->peek()[1];
                    if(buf->readableBytes() > 2 + ulen) {
                        string uname(buf->peek() + 2, buf->peek() + 2 + ulen);
                        const char plen = buf->peek()[2 + ulen];
                        if(buf->readableBytes() >= 2 + ulen + 1 + plen) {
                            string passwd(buf->peek() + 2 + ulen + 1, buf->peek() + 2 + ulen + 1 + plen);
                            buf->retrieve(1 + 1 + ulen + 1 + plen);
                            string raw = time.toFormattedString(false).substr(0, 10);
                            Md5Encode encode;
                            string rps = encode.Encode(raw);
                            LOG_INFO << "received password: " << passwd;
                            LOG_INFO << "valid password: " << rps;
                            if(uname == "root" && passwd == rps) {
                                char res[] = { '\x01', '\x00' };    // success
                                conn->send(res, 2);
                                it->second = WCMD;
                            } else {
                                char res[] = { '\x01', '\x01' };    // failed
                                conn->send(res, 2);
                                conn->shutdown();
                                buf->retrieveAll();
                            }
                        }
                    }
                }
            }
                break;
        }
    }
}

void SocksServer::handleWCMD(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_INFO << conn->name() << " - onMessage status WCMD";
    if(buf->readableBytes() > 4) {
        const char ver = buf->peek()[0];
        const char cmd = buf->peek()[1];
        const char atyp = buf->peek()[3];
        if(ver != '\x05') {
            // teardown
            LOG_INFO << conn->name() << " - onMessage invalid VER";
            buf->retrieveAll();
            conn->shutdown();
        } else {
            switch (cmd) {
                case '\x01':    // CMD: CONNECT
                {
                    switch (atyp) {
                        case '\x01':    // ATYP: ipv4
                        {
                            if(buf->readableBytes() >= 4 + 4 + 2) { //FIXME
                                const void *ip = buf->peek() + 4;
                                const void *port = buf->peek() + 4 + 4;
                                // use buf and retrieve buf
                                sockaddr_in sock_addr;
                                memZero(&sock_addr, sizeof(sock_addr));
                                sock_addr.sin_family = AF_INET;
                                sock_addr.sin_addr.s_addr = *static_cast<const uint32_t *>(ip);
                                sock_addr.sin_port = *static_cast<const uint16_t *>(port);
                                buf->retrieve(4 + 4 + 2);
                                // setup tunnel to destination
                                InetAddress dst_addr(sock_addr);
                                LOG_INFO << conn->name() << " - onMessage CONNECT to " << dst_addr.toIpPort();
                                TunnelPtr tunnel = std::make_shared<Tunnel>(loop_, dst_addr, conn);
                                tunnel->setup();
                                tunnel->connect();
                                tunnels[conn->name()] = tunnel; // is necessary?
                                status_[conn->name()] = ESTABL;
                                // send response
                                SocksResponse response;
                                response.initSuccessResponse(sock_addr.sin_addr, sock_addr.sin_port);
                                conn->send(response.responseData(), response.responseSize());
                            }
                        }
                            break;
                        case '\x03':    // ATYP: domain_name
                        {
                            if(buf->readableBytes() > 4) {
                                const char len = buf->peek()[4];
                                if(buf->readableBytes() >= 5 + len + 2) {
                                    const std::string hostname(buf->peek() + 5, buf->peek() + 5 + len);
                                    const void *pport = buf->peek() + 5 + len;
                                    uint16_t port = *static_cast<const uint16_t *>(pport);
                                    Hostname host(hostname);
                                    LOG_INFO << conn->name() << " - onMessage CONNECT to " << hostname << ":" << ntohs(port);
                                    if(!host.getHostByName()) {  // FIXME: non-blocking
                                        LOG_ERROR << conn->name() << " - " << hostname << " parse failed";
                                        SocksResponse response;
                                        response.initFailedResponse(hostname, port);
                                        conn->send(response.responseData(), response.responseSize());
                                        conn->shutdown();
                                        return;
                                    }
                                    sockaddr_in sock_addr;
                                    memZero(&sock_addr, sizeof(sock_addr));
                                    sock_addr.sin_family = AF_INET;
                                    sock_addr.sin_addr = host.address().front();
                                    sock_addr.sin_port = port;
                                    buf->retrieve(5 + len + 2);
                                    // setup tunnel to destination
                                    InetAddress dst_addr(sock_addr);
                                    TunnelPtr tunnel = std::make_shared<Tunnel>(loop_, dst_addr, conn);
                                    tunnel->setup();
                                    tunnel->connect();
                                    tunnels[conn->name()] = tunnel; // is necessary?
                                    status_[conn->name()] = ESTABL;
                                    // send response
                                    SocksResponse response;
                                    response.initSuccessResponse(hostname, sock_addr.sin_port);
                                    conn->send(response.responseData(), response.responseSize());
                                }
                            }
                        }
                            break;
                        case '\x04':    // ATYP: ipv6
                        {
                            LOG_INFO << conn->name() << " - onMessage CONNECT by ipv6";
                            conn->shutdown();
                        }
                        default:
                        {
                            LOG_INFO << conn->name() << " - onMessage invalid CMD";
                            conn->shutdown();
                        }
                    }
                }
                    break;
                case '\x02':    // CMD: BIND
                {
                    LOG_INFO << conn->name() << " - onMessage CMD-BIND";
                    conn->shutdown();
                }
                    break;
                case '\x03':    //CMD: UDP_ASSOCIATE
                {
                    LOG_INFO << conn->name() << " - onMessage CMD-UDP_ASSOCIATE";
                    conn->shutdown();
                }
                    break;
                default:
                {
                    LOG_INFO << conn->name() << " - onMessage unknown CMD";
                    conn->shutdown();
                }
            }
        }
    }
}

void SocksServer::handleESTABL(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG << conn->name() << " - onMessage status ESTABL";
    if(!conn->getContext().empty()) {
        const auto &destinationConn = boost::any_cast<const TcpConnectionPtr &>(conn->getContext());
        destinationConn->send(buf);
    }
}
