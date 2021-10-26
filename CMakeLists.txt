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
    src/tools.cpp
    src/instrumenter.cpp
    src/pe.cpp
    src/mem_tool.cpp
    src/translator.cpp
    )

add_executable(boxer
    src/main.cpp
    src/debugger.cpp
    )

target_link_libraries(boxer
    boxer_lib
    "dbghelp.lib"
    )

enable_language(ASM_NASM)
add_executable(program
    src/program.asm
    )
set_property(TARGET program 
    APPEND_STRING PROPERTY LINK_FLAGS " /ENTRY:WinMain"
    )
