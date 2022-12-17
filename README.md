# socks5
socks5 proxy server use muduo

# usage
socks5 \<listen port\>

# version
- 20221025

  Fixed memory leak due to FILE*.
  
  Realize the function of CONNECT without authentification.
  
  Realize a simple connection white list.
  
- 20221217
  
  Realize password validate
  
# TODO
- Realize UDP_ASSOCIATE.

# FIXME
- non-blocking getHostByName() in Hostname.cpp

