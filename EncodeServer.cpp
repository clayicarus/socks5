//
// Created by clay on 12/17/22.
//

#include <muduo/base/Logging.h>
#include "EncodeServer.h"
#include "MD5Encode.h"

std::string EncodeServer::keyGen(const std::string &raw) 
{
    Md5Encode encode;
    std::string rps = encode.Encode(raw);
    return rps;
}

void EncodeServer::onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp)
{
    LOG_INFO << conn->name() << " - get message";
    if(buf->readableBytes() > 255) {
        LOG_INFO << conn->name() << " - message too large";
        conn->shutdown();
    } else {
        auto s = keyGen(buf->retrieveAllAsString());
        conn->send(s);
    }
}

void EncodeServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_INFO << "EncodeServer - " << conn->peerAddress().toIpPort() << "->"
             << conn->localAddress().toIpPort() << " is "
             << (conn->connected() ? "UP" : "DOWN");
}