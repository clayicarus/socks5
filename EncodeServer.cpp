//
// Created by clay on 12/17/22.
//

#include <muduo/base/Logging.h>
#include "EncodeServer.h"
#include "base/SocksUtils.h"
#include "base/ValidateUtils.h"

void EncodeServer::onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp)
{
    // LOG_INFO << conn->name() << " - get message";
    LOG_WARN_CONN << "Receive message";
    if(buf->readableBytes() > 255) {
        LOG_ERROR_CONN << "Message too large";
        conn->shutdown();
    } else {
        auto s = genMD5(buf->retrieveAllAsString());
        conn->send(s);
    }
}

void EncodeServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_INFO_CONN << conn->peerAddress().toIpPort() << "->"
                  << conn->localAddress().toIpPort() << " is "
                  << (conn->connected() ? "UP" : "DOWN");
}