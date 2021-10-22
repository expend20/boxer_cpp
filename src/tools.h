#ifndef TOOLS_H
#define TOOLS_H

#include <string>
#include <windows.h>

namespace tools {
    std::string get_path_by_handle(HANDLE handle);
    std::string get_path_by_mod_name(const char* path, size_t max_chars);
    std::string get_mod_name_by_handle(HANDLE handle);
    std::string get_exception_name(DWORD code);
}

#endif // TOOLS_H
