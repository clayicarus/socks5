# socks5
socks5 proxy server use muduo

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
# TODO
- Realize UDP_ASSOCIATE.

# FIXME
- non-blocking getHostByName() in Hostname.cpp

