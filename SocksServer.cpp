//
// Created by clay on 10/22/22.
//

#include "SocksServer.h"
#include "base/SocksUtils.h"
#include "base/ConnectionQueue.h"
#include "base/ValidateUtils.h"
#include "base/SocksResponse.h"
#include "muduo/base/Logging.h"
#include "muduo/base/Timestamp.h"
#include "muduo/base/Types.h"
#include "muduo/net/Buffer.h"
#include "muduo/net/Callbacks.h"
#include "muduo/net/InetAddress.h"
#include "muduo/net/TcpConnection.h"
#include <algorithm>
#include <cassert>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
using namespace muduo;
using namespace muduo::net;

void SocksServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_INFO_CONN << conn->peerAddress().toIpPort() << "->"
                  << conn->localAddress().toIpPort() << " is "
                  << (conn->connected() ? "UP" : "DOWN");
    auto key = getNumFromConnName(conn->name());
    if(conn->connected()) {
        if (cq_.full()) {
            auto k = cq_.pop();  // forceClose a conn and reset message cb
            tunnels_.erase(k);
            status_.erase(k);
            LOG_WARN << "too many connections, actively shutdown #" << k
                     << "; current status count: " << status_.size() << ", peek: " << statusPeekCount_
                     << "; current tunnel count: " << tunnels_.size() << ", peek: " << tunnelPeekCount_;
        }
        conn->setTcpNoDelay(true);
        auto it = status_.find(key);
        if(it == status_.end()) {
            status_[key] = WREQ;
        }
        cq_[key] = std::weak_ptr<muduo::net::TcpConnection>(conn);
    } else {
        LOG_INFO_CONN << "source close";
        auto it = tunnels_.find(key);
        cq_.erase(key);
        if(it != tunnels_.end()) {
            LOG_INFO_CONN << "erase tunnel";
            tunnels_.erase(it);
        }
        auto is = status_.find(key);
        if(is != status_.end()) {
            LOG_INFO_CONN << "erase status";
            status_.erase(is);
        }
        conn->setMessageCallback(muduo::net::defaultMessageCallback);  // because tunnel die, it's not necessary to transfer data or to resolve request
    }
    tunnelPeekCount_ = std::max(tunnelPeekCount_, static_cast<int>(tunnels_.size()));
    statusPeekCount_ = std::max(statusPeekCount_, static_cast<int>(status_.size()));
    LOG_INFO_CONN << "current status count: " << status_.size() << ", peek: " << statusPeekCount_
                  << "; current tunnel count: " << tunnels_.size() << ", peek: " << tunnelPeekCount_;
}

void SocksServer::onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    assert(conn->connected());
    auto key = getNumFromConnName(conn->name());
    auto it = status_.find(key);  // use it->second for status changing
    auto status = it->second;
    switch(status) {
        case WREQ:
            handleWREQ(conn, buf, time);
            if (!(it->second != WREQ && buf->readableBytes())) {
                break;
            }
        case WVLDT:
            if (it->second == WVLDT) {  // for no-auth mode
                handleWVLDT(conn, buf, time);
                if (!(it->second != WVLDT && buf->readableBytes())) {
                    break;
                }
            }
        case WCMD:
            handleWCMD(conn, buf, time);
            if (!(it->second != WCMD && buf->readableBytes())) {
                break;
            }
        case ESTABL:
            handleESTABL(conn, buf, time);
            break;
    }
}

void SocksServer::handleWREQ(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_INFO_CONN << "status WREQ";
    auto key = getNumFromConnName(conn->name());
    auto it = status_.find(key);
    assert(it != status_.end() && it->second == WREQ);
    constexpr size_t headLen = 2;
    if(buf->readableBytes() < headLen) {
        return;
    }
    const char ver = buf->peek()[0];
    const char len = buf->peek()[1];
    if(ver != '\x05') {
        LOG_ERROR_CONN << "invalid VER";
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
    // TODO: use authentication map? just only two popular methods for authentication
    bool valid_method = false;
    char method;
    if (noAuth_) {
        method = '\x00';
        if (std::find(mthd, mthd + len, method) != mthd + len) {
            valid_method = true;
        }
    } else {
        method = '\x02';
        if (std::find(mthd, mthd + len, method) != mthd + len) {
            valid_method = true;
        }
    }
    if (!valid_method) {
        LOG_ERROR_CONN << "invalid authentication method";
        // response to invalid method, but won't send it
        char response[] = { ver, '\xff' };
        conn->send(response, sizeof(response));
        conn->forceClose();
        buf->retrieveAll();
    } else {
        LOG_INFO_CONN << "use method " << static_cast<int>(method);
        // send response for standard socks5
        char response[] { ver, method };
        conn->send(response, sizeof(response));
        if (noAuth_) {
            it->second = WCMD;
        } else {
            it->second = WVLDT;
        }
    }
}

void SocksServer::handleWVLDT(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_INFO_CONN << "status WVLDT";
    auto key = getNumFromConnName(conn->name());
    auto it = status_.find(key);
    assert(it != status_.end() && it->second == WVLDT);
    if(buf->readableBytes() < 2) {
        return;
    }
    const char ver = buf->peek()[0];
    const char ulen = buf->peek()[1];
    if(buf->readableBytes() < 2 + ulen) {
        return;
    }
    string recv_username(buf->peek() + 2, buf->peek() + 2 + ulen);
    const char plen = buf->peek()[2 + ulen];
    if(buf->readableBytes() < 2 + ulen + 1 + plen) {
        return;
    }
    string recv_pswd(buf->peek() + 2 + ulen + 1, buf->peek() + 2 + ulen + 1 + plen);
    buf->retrieve(1 + 1 + ulen + 1 + plen);
    bool access = false;
    if (useDynamicPassword_) {
        LOG_INFO_CONN << "authenticate with dynamic password";
        if (authenticateWithDynamicPassword(recv_username, recv_pswd)) {
            access = true;
        }
    } else if (!useDynamicPassword_) {
        LOG_INFO_CONN << "authenticate with config password";
        if (recv_username == username_ && recv_pswd == password_) {
            access = true;
        }
    }
    if (access) {
        // success including WREQ's response
        LOG_INFO_CONN << "authenticated";
        char res[] = { '\x01', '\x00' };
        conn->send(res, sizeof(res) / sizeof(char));
        it->second = WCMD;
    } else {
        // failed to validate, but won't send response
        LOG_ERROR_CONN << "invalid username / password - " << recv_username << " / " << recv_pswd;
        char res[] = { '\x01', '\x01' };
        conn->send(res, 2);
        conn->forceClose();
        buf->retrieveAll();
    }
}

void SocksServer::handleWCMD(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    LOG_INFO_CONN << "status WCMD";
    assert(status_.at(getNumFromConnName(conn->name())) == WCMD);
    if(buf->readableBytes() < 4) {
        return;
    }
    const char ver = buf->peek()[0];
    const char cmd = buf->peek()[1];
    if(ver != '\x05') {
        // teardown
        LOG_ERROR_CONN << "invalid VER";
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
                    LOG_INFO_CONN << "incompleted request head";
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
                    LOG_ERROR_CONN << "CONNECT: invalid ATYP";
                    shutdownSocksReq(conn, buf);
                    return;
            }
            auto wk = std::weak_ptr<TcpConnection>(conn);  // in case enlong lifetime
            parseSocksToInetAddress(loop_, p,
            [wk, buf, this, hostname, atyp, time](const InetAddress &dst_addr){
                auto conn = wk.lock();
                if (!conn || !conn->connected()) {
                    LOG_WARN << hostname << " resolved as " << dst_addr.toIpPort() << " but disconnected already";
                    return;
                }
                auto key = getNumFromConnName(conn->name());
                // if (!cq_.count(key)) {
                //     LOG_WARN << "Name resolved as " << dst_addr.toIpPort() << " but disconnected already";
                //     return;
                // }
                if (skipLocal_ && isLocalIP(dst_addr)) {
                    LOG_ERROR_CONN << "CONNECT: resolved to local address " << dst_addr.toIpPort();
                    shutdownSocksReq(conn, buf);
                    return;
                }
                LOG_INFO_CONN << "setup tunnel to resolved " << dst_addr.toIpPort();
                TunnelPtr tunnel = std::make_shared<Tunnel>(loop_, dst_addr, conn, highMarkKB_);
                tunnel->setup();
                tunnel->connect();
                tunnels_[key] = tunnel; // is necessary
                auto it = status_.find(key);
                if (it == status_.end()) {
                    LOG_FATAL_CONN << "missing status";
                }
                it->second = ESTABL;
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
                        LOG_FATAL_CONN << "CONNECT: invalid ATYP";
                }
                conn->send(response.responseData(), response.responseSize());
                if (buf->readableBytes() > 0) {
                    handleESTABL(conn, buf, time);
                }
            },
            [wk, hostname, buf]{
                auto conn = wk.lock();
                if (!conn) {
                    return;
                }
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
            LOG_ERROR_CONN << "unknown CMD";
            shutdownSocksReq(conn, buf);
            return;
    }
}

void SocksServer::handleESTABL(const TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time)
{
    // FIXME: If ESTABL only toggle once and conn->getContext() is empty, there will be some data not transfered to dst.
    //        It should not transfer data to dst here, but to transfer with tunnel (or notify tunnel to do it).

    // TODO: set message callback directly
    LOG_INFO_CONN << "status ESTABL";
    auto key = getNumFromConnName(conn->name());
    assert(status_.at(key) == ESTABL);
    auto tunnel_it = tunnels_.find(key);
    assert(tunnel_it != tunnels_.end());
    tunnel_it->second->onEstablishedSrcMessage(conn, buf, time);
}
