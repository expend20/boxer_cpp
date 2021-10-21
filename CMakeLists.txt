cmake_minimum_required(VERSION 2.8.9)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE on)

project("boxer_cpp")

include_directories(src)
include_directories(third_party)

add_library(boxer_lib
    src/Say.cpp
    src/args.cpp
    src/common.cpp
    )

add_executable(boxer
    src/main.cpp
    src/debugger.cpp
    )

target_link_libraries(boxer
    boxer_lib
    )
