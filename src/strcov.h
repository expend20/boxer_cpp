#ifndef _STRCOV_H_
#define _STRCOV_H_

#include "pe.h"

struct strcmp_data {
    std::vector<uint8_t> buf1;
    std::vector<uint8_t> buf2;
};

struct patched_addr {
    size_t addr = 0;
    size_t orig = 0;
};

struct patched_import {
    pehelper::import_module* module = 0;
    std::vector<patched_addr> data;
};

class strcmpcov {

    public:
        strcmpcov();
        ~strcmpcov();
        void clear_data(){ m_data.clear(); };
        void add_to_processing(uint8_t* p1, uint8_t* p2, size_t sz1, 
                size_t sz2);
        void install(std::vector<pehelper::import_module>* imports);
        void uninstall();
        std::vector<strcmp_data>* get_data(){ return &m_data; };

    private:

        static int __strcmp(char* str1, char* str2);
        static int __stricmp(char* str1, char* str2);
        static int __strncmp(char* str1, char* str2, size_t sz);
        static int __strnicmp(char* str1, char* str2, size_t sz);

        static int __wcsicmp(wchar_t *buf1, wchar_t *buf2);
        static int __wcsnicmp(void *buf1, void *buf2, size_t count);
        static int __wcsncmp(void *buf1, void *buf2, size_t count);
        static int __wcscmp(wchar_t *buf1, wchar_t *buf2);
        
        static int __memcmp(void *buf1, void *buf2, size_t count);

        bool should_check(){ return rand() % 100 == 0; };

    private:

        static strcmpcov* m_inst;
        std::vector<pehelper::import_module>* m_imports;
        std::vector<strcmp_data> m_data;
        bool m_stopped = false;
        std::vector<patched_import> m_patched_import;
        
};


#endif // _STRCOV_H_
