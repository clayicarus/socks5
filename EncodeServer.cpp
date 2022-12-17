//
// Created by clay on 12/17/22.
//

#include <muduo/base/Logging.h>
#include "EncodeServer.h"
#include "MD5Encode.h"

void EncodeServer::onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp)
{
    LOG_INFO << conn->name() << " - get message";
    if(buf->readableBytes() > 255) {
        LOG_INFO << conn->name() << " - message too large";
        buf->retrieveAll();
        conn->forceClose();
    } else {
        Md5Encode encode;
        auto s = encode.Encode(buf->retrieveAllAsString());
        conn->send(s);
    }
}

void EncodeServer::onConnection(const muduo::net::TcpConnectionPtr &conn)
{
    LOG_INFO << "EncodeServer - " << conn->peerAddress().toIpPort() << "->"
             << conn->localAddress().toIpPort() << " is "
             << (conn->connected() ? "UP" : "DOWN");
}