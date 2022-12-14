#ifndef __PE_H
#define __PE_H

#include "mem_tool.h"

#include <stdint.h>
#include <list>
#include <string>
#include <vector>
#include <windows.h>

namespace pehelper {

    struct section {
            std::string          name;
            IMAGE_SECTION_HEADER sect_head;
            mem_tool             data;
            size_t               mod_base = 0;
    };

#ifdef _WIN64
    // Same as RUNTIME_FUNCION but with fixed pointers
    struct runtime_function {
        size_t begin;
        size_t end;
        size_t data;
        size_t rtPtr;
        size_t handlerData;
        size_t handlerCallback;
    };

    /*
     * There are lots of functions which are represented not only by one
     * record but the series of chunks. In this case there is a magic trait:
     * each chunk in a serie is pointing to next one. The end of last chunk will
     * never point to the start of the next function.
     */

    struct runtime_function_united {
        size_t begin;
        size_t end;
    };
#endif

    struct import_function {
        std::string name;
        size_t externAddr; // address within the self module
    };

    struct import_module {
        std::string name;
        std::vector<import_function> funcs;
        section* sect = 0;
    };

    class pe {

        private:
            size_t m_remote_addr = 0;
            size_t m_remote_size = 0;
            HANDLE m_process = INVALID_HANDLE_VALUE;
        #ifdef _WIN64
            IMAGE_NT_HEADERS64 *m_nt_headers = NULL;
        #else
            IMAGE_NT_HEADERS *m_nt_headers = NULL;
        #endif
            mem_tool m_img_header;
            std::vector<section> m_sections;
            std::vector<import_module> m_import;
        #ifdef _WIN64
            std::vector<runtime_function> m_exception_funcs;
            std::vector<runtime_function_united> m_exception_united_funcs;
        #endif

        public:
            pe(){};
            pe(HANDLE process, size_t data);

            size_t            get_remote_addr(){ return m_remote_addr; };
            IMAGE_NT_HEADERS* get_nt_headers(){ return m_nt_headers; };
            mem_tool*         get_headers(){ return &m_img_header; };

            size_t            get_section_count();
            section*          get_section(size_t addr);
            section*          get_section(std::string name);
            section*          get_section_by_idx(size_t idx);
            std::vector<import_module>* get_imports(){ return &m_import; };

        #ifdef _WIN64
            runtime_function*  get_runtime_function(size_t rip);
            runtime_function_united*  get_runtime_function_united(size_t rip);
            std::vector<runtime_function>* get_runtime_functions();
        #endif

            void              extract_exception_directory();
            void              extract_sections();
            void              extract_imports();
    };

};
#endif // __PE_H
