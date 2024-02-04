//
// Created by clay on 12/17/22.
//

#include <muduo/base/Logging.h>
#include "EncodeServer.h"
#include "base/ValidateUtils.h"

void EncodeServer::onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp)
{
    LOG_INFO << "EncodeServer - " << conn->peerAddress().toIpPort() << "->" << conn->name() 
             << " - get message";
    if(buf->readableBytes() > 255) {
        LOG_WARN << "EncodeServer - " << conn->peerAddress().toIpPort() << "->" << conn->name()
                 << " - message too large";
        conn->shutdown();
    } else {
        auto s = genMD5(buf->retrieveAllAsString());
        conn->send(s);
    }
}

void EncodeServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_INFO << "EncodeServer - " << conn->peerAddress().toIpPort() << "->"
             << conn->localAddress().toIpPort() << " is "
             << (conn->connected() ? "UP" : "DOWN");
}