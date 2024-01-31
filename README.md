# socks5
socks5 proxy server use muduo

socks5 is a networking protocol used for proxy forwarding between a client and server. It allows clients to transmit network traffic through a proxy server to hide their real IP address, bypass firewalls, or protect their privacy.

Muduo is a C++-based networking library that provides high-performance non-blocking I/O and multi-threaded programming functionality. The library is based on an event-driven design pattern, making it easy for developers to build high-performance network applications.

# usage
socks5 \<listen port\>

# version
- 2022/10/25

  Fixed memory leak due to FILE*.
  
  Realize the function of CONNECT without authentification.
  
  Realize a simple connection white list.
  
- 2022/12/17
  
  Realize password validate
  
- 2022/12/19

  - debug about segment fault
  - use SocksResponse
  - follow RFC1928
  
- 2023/05/20

  - response correctly for source close actively
  - multiple validation mode
  - precise log info
  - fix bug about socks response
  - give up retry in several times 
# TODO
- Realize UDP_ASSOCIATE.

# FIXME
- non-blocking getHostByName() in Hostname.cpp

