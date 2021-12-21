/*
 * This module is designed to prevent target from leaking the memory when 
 * fuzzing iteration was abruptly stopped (e.g. crash or exception or timeout).
 * We're hooking memory allocations, record them and calling free() in between
 * the iterations
 */
#ifndef _LEAKS_H_
#define _LEAKS_H_

#include "pe.h"
#include <map>

struct leak_info {
    size_t handle = 0;
    size_t size = 0;
    size_t meta = 0;
};

struct leaks_stats {
    size_t allocs = 0;
    size_t frees = 0;
    size_t total_alloc = 0;
    size_t total_free = 0;
};

class leaks {
    public:
        leaks();
        ~leaks();

        void install(std::vector<pehelper::import_module>* imports);
        void uninstall();
        void free_all();

    private:
        static CRITICAL_SECTION m_crit_sect;
        std::map<size_t, leak_info> m_data;
        bool m_stopped = false;
        std::vector<std::pair<size_t, size_t>> m_saved;
        leaks_stats m_stats;



    private:
        void* add_to_processing(size_t size);
        void remove_from_processing(size_t addr);

    private:
        static leaks* m_inst;
        static void* __malloc(size_t size);
        static void* __calloc(size_t count, size_t size);
        static void __free(size_t addr);
        // TODO:
        // HeapAlloc
        // strdup
        // wcsdup
        // mbsdup
};
#endif //_LEAKS_H_
