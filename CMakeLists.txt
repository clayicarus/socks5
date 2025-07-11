cmake_minimum_required(VERSION 3.10)
project(socks5)

set(CMAKE_CXX_STANDARD 17)

# ASAN支持
option(ENABLE_ASAN "Enable AddressSanitizer" ON)
if(ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
    message(STATUS "ASAN is enabled")
else()
    set(CMAKE_EXE_LINKER_FLAGS "-static")
    message(STATUS "ASAN is disabled")
endif()

# nlohmann_json
set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(third_party/json)

# 集成muduo库
# 禁用muduo的示例构建，因为我们只需要库
set(MUDUO_BUILD_EXAMPLES OFF CACHE INTERNAL "")
add_subdirectory(third_party/muduo)

# 查找必要的依赖项
find_package(Threads REQUIRED)

set(SOURCE_FILE
        SocksServer.cpp
        EncodeServer.cpp
        base/MD5Encode.cpp
        base/SocksResponse.cpp
        base/ValidateUtils.cpp
        base/SocksUtils.cpp
)

# 创建可执行文件
add_executable(socks5 
        main.cpp
        ${SOURCE_FILE}
)

# 设置包含目录
target_include_directories(socks5 PRIVATE
        third_party/muduo
        third_party/muduo/examples
)

# 链接库并建立依赖关系
target_link_libraries(socks5 PRIVATE
        muduo_cdns
        muduo_net 
        muduo_base 
        Threads::Threads
        nlohmann_json::nlohmann_json
)
