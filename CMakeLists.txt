cmake_minimum_required(VERSION 2.8.9)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE on)

project("boxer_cpp")
add_subdirectory(third_party)

enable_language(ASM_NASM)

include_directories(src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)
include_directories(third_party)

add_subdirectory(src/tests)

link_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib)
#add_compile_options(-fsanitize=address)

add_library(boxer_lib
    src/say.cpp
    src/args.cpp
    src/common.cpp
    src/tools.cpp
    src/instrumenter.cpp
    src/pe.cpp
    src/mem_tool.cpp
    src/translator.cpp
    src/dasm.cpp
    src/mutator.cpp
    src/cov_tool.cpp
    src/strcov.cpp
    src/leaks.cpp
    src/leaks.cpp
    src/inproc_fuzzer.cpp
    src/inproc_harness.cpp
    src/ticker.cpp
    third_party/xxHash/xxhash.c
    )

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    add_library(asm_tools
        src/tools32.asm
        )
else()
    add_library(asm_tools
        src/tools64.asm
        )
endif()

add_library(dummy SHARED
    src/dummy_lib.cpp)

add_dependencies(boxer_lib xed)

add_executable(boxer
    src/main.cpp
    src/debugger.cpp
    )
target_link_libraries(boxer
    boxer_lib
    asm_tools
    "dbghelp.lib"
    "xed.lib"
    )

add_executable(boxer_veh
    src/main_veh.cpp
    src/veh.cpp
    )
target_link_libraries(boxer_veh
    boxer_lib
    asm_tools
    "dbghelp.lib"
    "xed.lib"
    )

add_executable(acctest
    src/acctest_adapter.cpp
    src/veh.cpp
    )
target_link_libraries(acctest
    boxer_lib
    asm_tools
    "dbghelp.lib"
    "xed.lib"
    )


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

# GoogleTest section
set(CMAKE_CXX_STANDARD 11)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(unittests
    src/ticker_unittest.cpp
    src/cov_unittest.cpp
)

target_link_libraries(unittests
    boxer_lib
    gtest_main
)

include(GoogleTest)
gtest_discover_tests(unittests)
