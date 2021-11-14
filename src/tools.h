#ifndef TOOLS_H
#define TOOLS_H

#include <string>
#include <windows.h>

namespace tools {
    std::string get_path_by_handle(HANDLE handle);
    std::string get_path_by_mod_name(const char* path, size_t max_chars);
    std::string get_mod_name_by_handle(HANDLE handle);
    std::string get_exception_name(DWORD code);

    size_t alloc_after_pe_image(
            HANDLE proc,
            size_t module_end, 
            size_t data_size,
            DWORD premissions);

    void write_minidump(const char* path, HANDLE proc, DWORD pid);
    void update_thread_rip(HANDLE thread, size_t rip);
    void update_thread_set_trap(HANDLE thread);

    void write_minidump(const char* path, 
            PROCESS_INFORMATION* pi,
            EXCEPTION_RECORD* ex_rec);
}

#endif // TOOLS_H
