//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include "base/SocksUtils.h"
#include "base/ValidateUtils.h"
#include "base/SocksResponse.h"
#include "muduo/base/Timestamp.h"
#include "muduo/base/Types.h"
#include "muduo/net/Buffer.h"
#include "muduo/net/Callbacks.h"
#include "muduo/net/InetAddress.h"
#include <algorithm>
#include <cassert>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
using namespace muduo;
using namespace muduo::net;

void SocksServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    tunnelMaxCount_ = std::max(tunnelMaxCount_, static_cast<int>(tunnels_.size()));
    statusMaxCount_ = std::max(statusMaxCount_, static_cast<int>(status_.size()));
    LOG_INFO_CONN << conn->peerAddress().toIpPort() << "->"
                  << conn->localAddress().toIpPort() << " is "
                  << (conn->connected() ? "UP" : "DOWN")
                  << ", current status count: " << status_.size() << ", max: " << statusMaxCount_
                  << ", current tunnel count: " << tunnels_.size() << ", max: " << tunnelMaxCount_;
    if(conn->connected()) {
        if (status_.size() >= 64) {
            LOG_WARN << "too many tunnels, force close " << conn->name(); 
            conn->forceClose();
            return;
        } 
        conn->setTcpNoDelay(true);
        auto it = status_.find(conn->name());
        if(it == status_.end()) {
            status_[conn->name()] = WREQ;
        }
    } else {
        LOG_INFO_CONN << "source close";
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
        LOG_FATAL_CONN << "Missing status";
    } else {
        auto status = it->second;
        switch(status) {
            case WREQ:
                handleWREQ(conn, buf, time);
                if(buf->readableBytes() == 0 || status_.at(conn->name()) != WVLDT) {
                    break;
                }
            case WVLDT:
                handleWVLDT(conn, buf, time);
                if(buf->readableBytes() == 0 || status_.at(conn->name()) != WCMD) {
                    break;
                }
            case WCMD:
                handleWCMD(conn, buf, time);
                if(buf->readableBytes() == 0 || status_.at(conn->name()) != ESTABL) {
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
    LOG_DEBUG_CONN << "Status WREQ";
    auto it = status_.find(conn->name());
    constexpr size_t headLen = 2;
    if(buf->readableBytes() < headLen) {
        return;
    }
    const char ver = buf->peek()[0];
    const char len = buf->peek()[1];
    if(ver != '\x05') {
        LOG_ERROR_CONN << "Invalid VER";
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
        // send response for standard socks5
        char response[] { ver, '\x02' };
        conn->send(response, 2);
        it->second = WVLDT;
    } else {
        // response to invalid method, but won't send it
        char response[] = {ver, '\xff'};
        conn->send(response, sizeof(response));
        buf->retrieveAll();
    }
}

void SocksServer::handleWVLDT(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG_CONN << "Status WVLDT";
    auto it = status_.find(conn->name());
    LOG_DEBUG_CONN << "Validate with dynamic password";
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
        char res[] = { '\x01', '\x00' };    
        conn->send(res, sizeof(res) / sizeof(char));
        it->second = WCMD;
    } else {
        // failed to validate, but won't send response
        char res[] = { '\x01', '\x01' };    
        conn->send(res, 2);
        LOG_ERROR_CONN << "Invalid username / password - " << uname << " / " << recv_pswd;
        buf->retrieveAll();
        // conn->shutdown();                // wait for source close, retrieve is necessary
    }
}

void SocksServer::handleWCMD(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG_CONN << "Status WCMD";
    if(buf->readableBytes() < 4) {
        return;
    }
    const char ver = buf->peek()[0];
    const char cmd = buf->peek()[1];
    if(ver != '\x05') {
        // teardown
        LOG_ERROR_CONN << "Invalid VER";
        buf->retrieveAll();
        conn->shutdown();
        return;
    } 
    switch (cmd) {
        case '\x01':    // CMD: CONNECT
        {
            auto p = buf->peek() + 3;
            auto addr = p + 1;
            auto atyp = testSocksAddressType(p, buf->readableBytes());
            std::string hostname {};
            InetAddress dst_addr {};
            switch (atyp) {
                case SocksAddressType::INCOMPLETED:
                    LOG_DEBUG_CONN << "Incompleted request head";
                    return;
                case SocksAddressType::IPv4:
                    dst_addr = parseSocksIPv4Port(addr);
                    if (skipLocal_ && isLocalIP(dst_addr)) {
                        LOG_ERROR_CONN << "CONNECT to local address " << dst_addr.toIpPort();
                        shutdownSocksReq(conn, buf);
                        return;
                    }
                    LOG_WARN_CONN << "CONNECT to IPv4 " << dst_addr.toIpPort();
                    break;
                case SocksAddressType::IPv6:
                    LOG_WARN_CONN << "CONNECT to IPv6 " << parseSocksIPv6Port(addr).toIpPort();
                    break;
                case SocksAddressType::DOMAIN_NAME:
                    LOG_WARN_CONN << "CONNECT to domain " << parseSocksDomainNamePort(addr);
                    hostname = parseSocksDomainName(addr);
                    break;
                case SocksAddressType::INVALID:
                    LOG_ERROR_CONN << "CONNECT: Invalid ATYP";
                    shutdownSocksReq(conn, buf);
                    return;
            }
            parseSocksToInetAddress(loop_, p, 
            [conn, buf, this, hostname, atyp, time](const InetAddress &dst_addr){
                if (skipLocal_ && isLocalIP(dst_addr)) {
                    LOG_ERROR_CONN << "CONNECT: Resolved to local address " << dst_addr.toIpPort();
                    shutdownSocksReq(conn, buf);
                    return;
                }
                LOG_INFO_CONN << "connect to resolved " << dst_addr.toIpPort();
                TunnelPtr tunnel = std::make_shared<Tunnel>(loop_, dst_addr, conn);
                tunnel->setup();
                tunnel->connect();
                tunnels_[conn->name()] = tunnel; // is necessary
                status_[conn->name()] = ESTABL;
                SocksResponse response {};
                switch (atyp) {
                    case SocksAddressType::IPv4:
                    {
                        in_addr addr_4 {};
                        addr_4.s_addr = dst_addr.ipv4NetEndian();
                        response.initSuccessResponse(addr_4, dst_addr.portNetEndian());
                        buf->retrieve(4 + 4 + 2);
                    }
                        break;
                    case SocksAddressType::DOMAIN_NAME:
                        response.initSuccessResponse(hostname, dst_addr.port());
                        buf->retrieve(4 + 1 + hostname.size() + 2);
                        break;
                    case SocksAddressType::IPv6:
                    {
                        in6_addr addr_6 {};
                        addr_6 = reinterpret_cast<const sockaddr_in6*>(dst_addr.getSockAddr())->sin6_addr;
                        response.initSuccessResponse(addr_6, dst_addr.portNetEndian());
                        buf->retrieve(4 + 16 + 2);
                    }
                        break;
                    case SocksAddressType::INCOMPLETED:
                    case SocksAddressType::INVALID:
                        LOG_FATAL_CONN << "CONNECT: Invalid ATYP";
                }
                conn->send(response.responseData(), response.responseSize());
                if (buf->readableBytes() > 0) {
                    handleESTABL(conn, buf, time);
                }
            }, 
            [hostname, conn, buf]{
                LOG_ERROR_CONN << hostname << " resolve failed";
                shutdownSocksReq(conn, buf);
            });
        }
            break;
        case '\x02':    // CMD: BIND
            LOG_ERROR_CONN << "BIND";
            shutdownSocksReq(conn, buf);
            break;
        case '\x03':    //CMD: UDP_ASSOCIATE
        {
            auto p = buf->peek() + 3;
            switch (testSocksAddressType(p++, buf->readableBytes())) {
                case SocksAddressType::INCOMPLETED: 
                    return;
                case SocksAddressType::IPv4:
                    LOG_WARN_CONN << "UDP_ASSOCIATE to IPv4 " << parseSocksIPv4Port(p).toIpPort();
                    break;
                case SocksAddressType::IPv6:
                    LOG_WARN_CONN << "UDP_ASSOCIATE to IPv6 " << parseSocksIPv6Port(p).toIpPort();
                    break;
                case SocksAddressType::DOMAIN_NAME:
                    LOG_WARN_CONN << "UDP_ASSOCIATE to domain " << parseSocksDomainNamePort(p);
                    break;
                case SocksAddressType::INVALID: 
                    shutdownSocksReq(conn, buf);
                    return;
            }
            SocksResponse rep;
            // FIXME: IPv6 or domain name
            in_addr addr {};
            addr.s_addr = associationAddr_.ipv4NetEndian();
            rep.initSuccessResponse(addr, associationAddr_.portNetEndian());
            conn->send(rep.responseData(), rep.responseSize());
            buf->retrieveAll();
        }
            break;
        default:
            LOG_ERROR_CONN << "Unknown CMD";
            shutdownSocksReq(conn, buf);
            return;
    }
}

void SocksServer::handleESTABL(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_DEBUG_CONN << "Status ESTABL";
    if(!conn->getContext().empty()) {
        const auto &destinationConn = boost::any_cast<const TcpConnectionPtr &>(conn->getContext());
        destinationConn->send(buf);
    } 
}
