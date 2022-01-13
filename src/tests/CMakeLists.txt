set(CMAKE_CXX_STANDARD 17)

enable_language(ASM_NASM)

if (${CMAKE_SIZEOF_VOID_P} EQUAL 4)
    add_library(acc_test SHARED
        acc_test.cpp
        test_x86.asm
        )
else()
    add_library(acc_test SHARED
        acc_test.cpp
        test.asm
        )
endif()

