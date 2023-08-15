//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include "base/Utils.h"
#include "base/SocksResponse.h"
#include "muduo/base/Logging.h"
#include "muduo/net/InetAddress.h"
#include <string>
using namespace muduo;
using namespace muduo::net;

void SocksServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() 
             << (conn->connected() ? " UP" : " DOWN");
    if(conn->connected()) {
        conn->setTcpNoDelay(true);
        auto it = status_.find(conn->name());
        if(it == status_.end()) {
            status_[conn->name()] = WREQ;
        }
    } else {
        auto it = tunnels_.find(conn->name());
        if(it != tunnels_.end()) {
            it->second->disconnect();
            tunnels_.erase(it);
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
        LOG_FATAL << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - without status";
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
            case RESOLVING:
                LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - recv messages when resolving";
                break;
        }
    }
}

void SocksServer::handleWREQ(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - status WREQ";
    auto it = status_.find(conn->name());
    constexpr size_t headLen = 2;
    if(buf->readableBytes() < headLen) {
        return;
    }
    const char ver = buf->peek()[0];
    const char len = buf->peek()[1];
    if(ver != '\x05') {
        LOG_ERROR << conn->peerAddress().toIpPort()  << "->" << conn->name() 
                  << " - onMessage - invalid VER";
        buf->retrieveAll();
        conn->shutdown();
        return;
    }
    if(buf->readableBytes() < headLen + len) {
        return;
    }
    const char *mthd = buf->peek() + 2;
    buf->retrieve(headLen + len);   // read and retrieve !!
    // x02 password authentication, x00 none, xff invalid
    // only for passsword auth
    if(std::find(mthd, mthd + len, '\x02') != mthd + len) {
        // available auth response, don't send it until validate successfully
        // char response[] = "V\x02";
        // response[0] = ver;
        // conn->send(response, 2);
        it->second = WVLDT;
    } else {
        // response to invalid method, but won't send it
        // char response[] = "V\xff";
        // response[0] = ver;
        // conn->send(response, 2);
        buf->retrieveAll();
    }
}

void SocksServer::handleWVLDT(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - status WVLDT";
    auto it = status_.find(conn->name());
    LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - validate with dynamic password";
    if(buf->readableBytes() < 2) {
        return;
    }
    const char ver = buf->peek()[0];
    const char ulen = buf->peek()[1];
    if(buf->readableBytes() < 2 + ulen) {
        return;
    }
    string uname(buf->peek() + 2, buf->peek() + 2 + ulen);
    const char plen = buf->peek()[2 + ulen];
    if(buf->readableBytes() < 2 + ulen + 1 + plen) {
        return;
    }
    string recv_pswd(buf->peek() + 2 + ulen + 1, buf->peek() + 2 + ulen + 1 + plen);
    buf->retrieve(1 + 1 + ulen + 1 + plen);
    if(authenticate(uname, recv_pswd)) {
        // success including WREQ's response
        char res[] = { '\x05', '\x02', '\x01', '\x00' };    
        conn->send(res, sizeof(res) / sizeof(char));
        it->second = WCMD;
    } else {
        // failed to validate, but won't send response
        // char res[] = { '\x01', '\x01' };    
        // conn->send(res, 2);
        LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name()
                    << " - invalid username / password: " << uname << " / " << recv_pswd;
        buf->retrieveAll();
        // conn->shutdown();                // wait for source close, retrieve is necessary
    }
}

bool isValidIP(const InetAddress &addr)
{
    auto ip_prefix = addr.toIp().substr(0, addr.toIp().find('.'));
    if(ip_prefix == "0" || ip_prefix == "127" || ip_prefix == "192") {
        return false;
    }
    return true;
}

void SocksServer::handleWCMD(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - status WCMD";
    if(buf->readableBytes() < 4) {
        return;
    }
    const char ver = buf->peek()[0];
    const char cmd = buf->peek()[1];
    const char atyp = buf->peek()[3];
    if(ver != '\x05') {
        // teardown
        LOG_ERROR << conn->peerAddress().toIpPort()  << "->" << conn->name() 
                  << " - onMessage - invalid VER";
        buf->retrieveAll();
        conn->shutdown();
        return;
    } 
    switch (cmd) {
        case '\x01':    // CMD: CONNECT
        {
            switch (atyp) {
                case '\x01':    // ATYP: ipv4
                {
                    if(buf->readableBytes() < 4 + 4 + 2) {
                        return;
                    }
                    //FIXME
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
                    if (!isValidIP(dst_addr)) {
                        LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - request to invalid address " << dst_addr.toIpPort();
                        SocksResponse response;
                        response.initFailedResponse(dst_addr.toIp(), dst_addr.port());
                        conn->send(response.responseData(), response.responseSize());
                        buf->retrieveAll();
                        return;
                    }
                    LOG_INFO << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - CONNECT to " << dst_addr.toIpPort();
                    TunnelPtr tunnel = std::make_shared<Tunnel>(loop_, dst_addr, conn);
                    tunnel->setup();
                    tunnel->connect();
                    tunnels_[conn->name()] = tunnel; // is necessary
                    SocksResponse response;
                    status_[conn->name()] = ESTABL;
                    // send response
                    response.initSuccessResponse(sock_addr.sin_addr, sock_addr.sin_port);
                    conn->send(response.responseData(), response.responseSize());
                }
                    break;
                case '\x03':    // ATYP: domain_name
                {
                    if(buf->readableBytes() <= 4) {
                        return;
                    }
                    const char len = buf->peek()[4];
                    if(buf->readableBytes() < 5 + len + 2) {
                        return;
                    }
                    const std::string hostname(buf->peek() + 5, buf->peek() + 5 + len);
                    const void *pport = buf->peek() + 5 + len;
                    uint16_t port = *static_cast<const uint16_t *>(pport);  // network endian
                    buf->retrieve(5 + len + 2);
                    LOG_INFO << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - CONNECT to " << hostname << ":" << ntohs(port);
                    status_[conn->name()] = RESOLVING;
                    resolver_.resolve(hostname, [this, conn, buf, time, hostname, port](const InetAddress &addr){
                        // FIXME if conn dtor before resolved
                        InetAddress des{addr.toIp(), ntohs(port)};
                        LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() 
                                 << " - onMessage - " << hostname << " parsed as " << des.toIpPort();
                        onResolved(conn, buf, des);
                    });
                }
                    break;
                case '\x04':    // ATYP: ipv6
                {
                    LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - CONNECT by ipv6";
                    SocksResponse rep;
                    rep.initGeneralResponse('\x07');
                    conn->send(rep.responseData(), rep.responseSize());
                    buf->retrieveAll();
                }
                default:
                {
                    LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - invalid ATYP";
                    SocksResponse rep;
                    rep.initGeneralResponse('\x07');
                    conn->send(rep.responseData(), rep.responseSize());
                    buf->retrieveAll();
                }
            }
        }
            break;
        case '\x02':    // CMD: BIND
        {
            LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - CMD-BIND";
            SocksResponse rep;
            rep.initGeneralResponse('\x07');
            conn->send(rep.responseData(), rep.responseSize());
            buf->retrieveAll();
        }
            break;
        case '\x03':    //CMD: UDP_ASSOCIATE
        {
            LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - CMD-UDP_ASSOCIATE";
            SocksResponse rep;
            rep.initGeneralResponse('\x07');
            conn->send(rep.responseData(), rep.responseSize());
            buf->retrieveAll();
        }
            break;
        default:
            LOG_WARN << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - unknown CMD";
            SocksResponse rep;
            rep.initGeneralResponse('\x07');
            conn->send(rep.responseData(), rep.responseSize());
            buf->retrieveAll();
    }
}

void SocksServer::onResolved(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, const muduo::net::InetAddress &addr)
{
    SocksResponse response;
    // FIXME: more effective way to judge if resolve failed
    if (!isValidIP(addr)) {
        response.initFailedResponse(addr.toIp(), addr.port());
        conn->send(response.responseData(), response.responseSize());
        buf->retrieveAll();
        return;
    }
    TunnelPtr tunnel = std::make_shared<Tunnel>(loop_, addr, conn);
    tunnel->setup();
    tunnel->connect();
    tunnels_[conn->name()] = tunnel; // is necessary
    status_[conn->name()] = ESTABL;
    // send response
    response.initSuccessResponse(in_addr {addr.ipv4NetEndian()}, addr.port());
    conn->send(response.responseData(), response.responseSize());
    if(buf->readableBytes() > 0) {
        handleESTABL(conn, buf, Timestamp::now());
    }
}

void SocksServer::handleESTABL(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG << conn->peerAddress().toIpPort()  << "->" << conn->name() << " - onMessage - status ESTABL";
    if(!conn->getContext().empty()) {
        const auto &destinationConn = boost::any_cast<const TcpConnectionPtr &>(conn->getContext());
        destinationConn->send(buf);
    } 
}
