#ifndef UDP_ASSOCIATE_H
#define UDP_ASSOCIATE_H

#include "muduo/base/Logging.h"
#include "muduo/cdns/Resolver.h"
#include "muduo/net/Channel.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include "base/SocksUtils.h"

// thread not safe
class UdpTunnel {
    constexpr static size_t UDP_TUNNEL_BUF_SZ { 65536 };
public:
    using MessageFilter = std::function<std::string(const std::string&)>;

    UdpTunnel(const UdpTunnel &) = delete;
    ~UdpTunnel()
    {
        ch_->disableReading();
        ::close(ch_->fd());
    }
    UdpTunnel(muduo::net::EventLoop *loop,
              const muduo::net::InetAddress &src,
              int src_fd) :
    buf_(), src_fd_(src_fd), src_(src), ch_(), message_filter_([](const auto &msg) { return msg; })
    {
        auto fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOG_FATAL << "Socket < 0";
        }
        ch_.reset(new muduo::net::Channel(loop, fd));
        assert(ch_);
        ch_->setReadCallback([this](muduo::Timestamp timestamp) { messageCallback(timestamp); });
        ch_->enableReading();
    }
    // FIXME: receive data not from dst
    ssize_t send(const void *buf, size_t n, const muduo::net::InetAddress &dst) const
    {
        // TODO: flag for what
        return sendto(ch_->fd(), buf, n, 0, dst.getSockAddr(), sizeof(sockaddr));
    }
    void setMessageFilter(MessageFilter filter_) { std::swap(filter_, message_filter_); }
    void resetMessageFilter() { message_filter_ = [](const auto &msg) { return msg; }; }
private:
    ssize_t sendBackToSrc(const void *buf, size_t n) const
    {
        return sendto(src_fd_, buf, n, 0, src_.getSockAddr(), sizeof(sockaddr));
    }
    void messageCallback(muduo::Timestamp timestamp)
    {
        LOG_DEBUG << "fd " << ch_->fd() << " readable on " << timestamp.toFormattedString();
        sockaddr_in addr {};
        muduo::memZero(&addr, sizeof(addr));
        socklen_t len { sizeof(addr) };
        auto rcv_len = recvfrom(ch_->fd(), buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&addr), &len);
        if (rcv_len < 0) {
            LOG_FATAL << "rcv_len < 0";
        }
        muduo::net::InetAddress dst_addr(addr);
        LOG_INFO << rcv_len << " bytes received from " << dst_addr.toIpPort();
        std::string res = message_filter_(std::string(buf_, buf_ + rcv_len));
        auto snt_len = sendBackToSrc(res.c_str(), res.size());
        LOG_INFO << snt_len << " bytes from " << dst_addr.toIpPort() << " sent back to " << src_.toIpPort();
    }

    char buf_[UDP_TUNNEL_BUF_SZ];
    int src_fd_;
    muduo::net::InetAddress src_;
    std::unique_ptr<muduo::net::Channel> ch_;
    MessageFilter message_filter_;
};

// TODO: src restrict
// TODO: frag
class UdpAssociation {
    constexpr static size_t UDP_ASSOCIATION_BUF_SZ { 65536 };
public:
    using Tunnel = std::unique_ptr<UdpTunnel>;

    UdpAssociation(const UdpAssociation &) = delete;
    ~UdpAssociation() 
    { 
        ch_->disableReading();
        ::close(ch_->fd()); 
    }
    explicit UdpAssociation(muduo::net::EventLoop *loop, const muduo::net::InetAddress &association_addr): 
        loop_(loop), skip_local_address_(true)
    {
        auto fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOG_FATAL << "Socket < 0";
        }
        auto ret = ::bind(fd, association_addr.getSockAddr(), sizeof(sockaddr));
        if (ret < 0) {
            LOG_FATAL << "Bind < 0";
        }
        ch_.reset(new muduo::net::Channel(loop, fd));
        ch_->setReadCallback([this](muduo::Timestamp timestamp) {
            readCallback(timestamp);
        });
        ch_->enableReading();
        LOG_INFO << "Association start on " << association_addr.toIpPort();
    }
    bool isSkipLocal() const { return skip_local_address_; }
    void skipLocal(bool skip=true) { skip_local_address_ = skip; }
private:
    void readCallback(muduo::Timestamp timestamp)
    {
        LOG_DEBUG << "Association readable on " << timestamp.toFormattedString();
        sockaddr_in addr {};
        muduo::memZero(&addr, sizeof(sockaddr_in));
        socklen_t len { sizeof(addr) };
        auto rcv_len = recvfrom(ch_->fd(), buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&addr), &len);
        muduo::net::InetAddress from_addr(addr);
        if (rcv_len < 0) { 
            LOG_FATAL << "recvfrom";
        }
        if (rcv_len <= 4) return;
        // TODO: frag
        if (std::string(buf_, buf_ + 3) != std::string { '\x00', '\x00', '\x00' }) return;
        auto p = buf_ + 3;
        char *data {};
        switch (testSocksAddressType(p, rcv_len)) {
            case SocksAddressType::IPv4:
            data = p + 1 + 4 + 2;
            break;
            case SocksAddressType::IPv6:
            data = p + 1 + 16 + 2;
            break;
            case SocksAddressType::DOMAIN_NAME:
            data = p + 1 + p[1] + 2;
            break;
            case SocksAddressType::INCOMPLETED:
            case SocksAddressType::INVALID:
            return;
        }
        auto head_len = std::distance(buf_, data);
        auto data_len = rcv_len - head_len;
        std::string head(buf_, buf_ + head_len);
        parseSocksToInetAddress(loop_, p, 
        [this, data, data_len, head, from_addr](const auto &dst_addr) {
            if (skip_local_address_ && isLocalIP(dst_addr)) {
                LOG_WARN << "ASSOCIATE to local address " << dst_addr.toIpPort();
                return;
            }
            auto key = from_addr.toIpPort();
            if (!association_.count(key)) {
                auto p = association_.insert({ key, std::unique_ptr<UdpTunnel>() });
                p.first->second.reset(new UdpTunnel(loop_, from_addr, ch_->fd()));
                p.first->second->setMessageFilter([head](const auto &msg) {
                    return head + msg;
                });
            }
            auto sent_len = association_[key]->send(data, data_len, dst_addr);
            if (sent_len < 0) {
                LOG_ERROR << "send error";
            }
            LOG_INFO << sent_len << " bytes from " << from_addr.toIpPort() << " associate to " << dst_addr.toIpPort();
        }, 
        []{
            LOG_WARN << " parse failed";
        });
    }

    char buf_[UDP_ASSOCIATION_BUF_SZ];
    std::unique_ptr<muduo::net::Channel> ch_;
    // FIXME: memory leak
    std::map<std::string, Tunnel> association_;
    muduo::net::EventLoop *loop_;
    bool skip_local_address_;
};

#endif  // UDP_ASSOCIATE_H