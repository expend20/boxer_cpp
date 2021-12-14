#ifndef _STRCOV_H_
#define _STRCOV_H_

#include "pe.h"

struct strcmp_data {
    std::vector<uint8_t> buf1;
    std::vector<uint8_t> buf2;
    bool should_add_zero = false;
};

class strcmpcov {

    public:
        strcmpcov();
        ~strcmpcov();
        void clear_data(){ m_data.clear(); };
        void add_to_processing(uint8_t* p1, uint8_t* p2, size_t sz,
                bool ignore_case);
        void install(std::vector<pehelper::import_module>* imports);
        void uninstall();
        std::vector<strcmp_data>* get_data(){ return &m_data; };

    private:
        static strcmpcov* m_inst;
        static int __strcmp(char* str1, char* str2);
        static int __stricmp(char* str1, char* str2);
        static int __strncmp(char* str1, char* str2, size_t sz);
        static int __strnicmp(char* str1, char* str2, size_t sz);
        static int __memcmp(void *buf1, void *buf2, size_t count);
        
    private:
        std::vector<pehelper::import_module>* m_imports;
        std::vector<strcmp_data> m_data;
        bool m_stopped = false;
        std::vector<std::pair<size_t, size_t>> m_saved;
};


#endif // _STRCOV_H_
