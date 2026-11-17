cmake_minimum_required(VERSION 3.16)
project(ppceeder
    VERSION 0.1
    LANGUAGES C
)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Place binary executables in the build/bin directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTO REQUIRED libcrypto)

# Executable
add_executable(ppceeder
    dns/dns.c
    dns/dns.h

    log/log.c
    log/log.h

    message/addr-payload.c
    message/addr-payload.h
    message/bytes.c
    message/bytes.h
    message/endianness.h
    message/message.c
    message/message.h
    message/net-addr.c
    message/net-addr.h
    message/var-int.c
    message/var-int.h
    message/var-str.c
    message/var-str.h
    message/version-payload.c
    message/version-payload.h

    ppceeder/ppceeder.c
)
target_include_directories(ppceeder PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(ppceeder PRIVATE crypto)
