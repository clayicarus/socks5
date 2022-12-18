cmake_minimum_required(VERSION 3.23)
project(socks5)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_executable(socks5
        main.cpp
        tunnel.h SocksServer.cpp SocksServer.h
        Hostname.h Hostname.cpp MD5Encode.cpp MD5Encode.h EncodeServer.cpp EncodeServer.h SocksResponse.cpp SocksResponse.h)
target_link_libraries(socks5 muduo_net muduo_base pthread)