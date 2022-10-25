# socks5
socks5 proxy server use muduo
# usage
socks5 \<listen port\>
# version
- 20221025
  Fixed memory leak due to FILE*.
  Realize the function of CONNECT without authentification.
  Realize a simple connection white list.
# TODO
- Realize UDP_ASSOCIATE.
