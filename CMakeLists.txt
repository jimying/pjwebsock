cmake_minimum_required(VERSION 3.0...3.20 FATAL_ERROR)
project (pjwebsock C)

# Auto generate compile_commands.json for clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find libpjproject
find_package(PkgConfig REQUIRED)
pkg_check_modules(PJ REQUIRED libpjproject)

# Set cflags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# Set platform libs
set(PLATFORM_LIBS ${PLATFORM_LIBS} -lm -pthread)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(PLATFORM_LIBS ${PLATFORM_LIBS} -luuid)
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(PLATFORM_LIBS ${PLATFORM_LIBS} -framework Cocoa)
elseif(CMAKE_SYSTEM_NAME MATCHES "(OpenBSD|FreeBSD)")
    set(PLATFORM_LIBS ${PLATFORM_LIBS} -lcrypto -lssl)
endif()

# Build sub
add_subdirectory(websock)
add_subdirectory(tests)
