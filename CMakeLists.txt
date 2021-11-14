cmake_minimum_required(VERSION 2.8.9)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE on)

project("boxer_cpp")
add_subdirectory(third_party)

include_directories(src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)

link_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib)

add_library(boxer_lib
    src/Say.cpp
    src/args.cpp
    src/common.cpp
    src/tools.cpp
    src/instrumenter.cpp
    src/pe.cpp
    src/mem_tool.cpp
    src/translator.cpp
    src/dasm.cpp
    )

add_dependencies(boxer_lib xed)

add_executable(boxer
    src/main.cpp
    src/debugger.cpp
    )

target_link_libraries(boxer
    boxer_lib
    "dbghelp.lib"
    "xed.lib"
    )

enable_language(ASM_NASM)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    add_executable(program
        src/program32.asm
        )
else()
    add_executable(program
        src/program64.asm
        )
endif()

set_property(TARGET program 
    APPEND_STRING PROPERTY LINK_FLAGS " /ENTRY:WinMain"
    )
