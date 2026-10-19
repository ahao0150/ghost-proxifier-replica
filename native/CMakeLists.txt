cmake_minimum_required(VERSION 3.20)
project(gpp_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MINGW)
    add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8 -Wno-unknown-pragmas -Wno-cast-function-type)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

add_subdirectory(minhook minhook_build)

set(CORE_SOURCES
    core/ghost_core.cpp
    core/shellcode.cpp
    core/hooks_socket.cpp
    core/hooks_dns.cpp
    core/proxy.cpp
    core/udp.cpp
    core/ss.cpp
    core/dns.cpp
    core/dns_cache.cpp
    core/dns_pool.cpp
    core/config.cpp
    core/utils.cpp
)

add_library(gpp_core SHARED ${CORE_SOURCES})
target_include_directories(gpp_core PRIVATE core minhook/include)
target_link_libraries(gpp_core PRIVATE minhook ws2_32 iphlpapi psapi shell32 bcrypt)
set_target_properties(gpp_core PROPERTIES
    OUTPUT_NAME gpp_core_x64 PREFIX "" SUFFIX ".dll"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(gppctl ctl/main.cpp)
target_link_libraries(gppctl PRIVATE ws2_32 iphlpapi psapi shell32 ole32 oleaut32)
if(MINGW)
    target_link_options(gppctl PRIVATE -municode)
endif()
set_target_properties(gppctl PROPERTIES
    OUTPUT_NAME gppctl PREFIX "" SUFFIX ".exe"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
