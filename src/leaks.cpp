#include "leaks.h"
#include "say.h"

leaks *leaks::m_inst = 0;
CRITICAL_SECTION leaks::m_crit_sect;

void leaks::free_all()
{
    //if (m_stats.total_alloc - m_stats.total_free) 
    //SAY_INFO("Allocs %d, frees %d, alloc size %d, free size %d, leak size %d\n",
    //        m_stats.allocs, m_stats.frees, 
    //        m_stats.total_alloc, m_stats.total_free,
    //        m_stats.total_alloc - m_stats.total_free);
    //m_stats = {0};

    for (auto &[addr, info]: m_data) {
        if (!info.handle) {
            free((void*)addr);
        }
    }

    m_data.clear();
}

void leaks::remove_from_processing(size_t addr)
{
    EnterCriticalSection(&m_crit_sect);

    auto r = m_data.find(addr);
    if (r == m_data.end()) {
        SAY_ERROR("Attempt to free invalid memory at %p\n", addr);
    }
    else {
        //SAY_INFO("Memory freed: %p %x\n", r->first, r->second.size);
        m_stats.frees++;
        m_stats.total_free += r->second.size;
        m_data.erase(r);
    }

    LeaveCriticalSection(&m_crit_sect);
    free((void*)addr);
}

void* leaks::add_to_processing(size_t size)
{
    void* r = malloc(size);
    ASSERT(r);

    m_stats.allocs++;
    m_stats.total_alloc += size;

    leak_info li;
    li.size = size;

    //SAY_INFO("Allocation %p %x\n", r, size);

    EnterCriticalSection(&m_crit_sect);

    m_data[(size_t)r] = std::move(li);

    LeaveCriticalSection(&m_crit_sect);

    return r;
}

void leaks::install(std::vector<pehelper::import_module>* imports)
{
    for (auto &import: *imports) {

        import.sect->data.make_writeable();

        for (auto &func: import.funcs) {
            //SAY_INFO("%s.%s %p\n", import.name.c_str(), func.name.c_str(),
            //        func.externAddr);
            auto orig = *(size_t*)func.externAddr;
            bool should_save = false;

            if (!strcmp(func.name.c_str(), "malloc") ||
                    !strcmp(func.name.c_str(), "_o_malloc")) {
                SAY_INFO("Patching malloc: %p -> %p\n", func.externAddr,
                        __malloc);
                *(size_t*)func.externAddr = (size_t)__malloc;
                should_save = true;
            }
            if (!strcmp(func.name.c_str(), "calloc") ||
                    !strcmp(func.name.c_str(), "_o_calloc")) {
                SAY_INFO("Patching calloc: %p -> %p\n", func.externAddr,
                        __calloc);
                *(size_t*)func.externAddr = (size_t)__calloc;
                should_save = true;
            }
            else if (!strcmp(func.name.c_str(), "free") ||
                    !strcmp(func.name.c_str(), "_o_free")) {
                SAY_INFO("Patching free: %p -> %p\n", func.externAddr,
                        __free);
                *(size_t*)func.externAddr = (size_t)__free;
                should_save = true;
            }

            if (should_save) 
                m_saved.push_back(std::make_pair(func.externAddr, orig));
        }
        import.sect->data.restore_prev_protection();
    }
}

void leaks::uninstall()
{
    for (auto &v: m_saved) {
        *(size_t*)v.first = v.second;
    }
    m_saved.clear();
}

void* leaks::__malloc(size_t size) {
    if (!m_inst->m_stopped) {
        auto res = m_inst->add_to_processing(size);
        return res;
    }
    else {
        return malloc(size);
    }
}

void* leaks::__calloc(size_t count, size_t size) {
    if (!m_inst->m_stopped) {
        auto res = m_inst->add_to_processing(size * count);
        return res;
    }
    else {
        return malloc(size);
    }
}

void leaks::__free(size_t addr) {
    if (!m_inst->m_stopped) {
        m_inst->remove_from_processing(addr);
    }
    else {
        free((void*)addr);
    }
}


leaks::leaks()
{
    if (m_inst) SAY_FATAL("Only one instance of strcmpcov allowed\n");
    m_inst = this;
    InitializeCriticalSection(&m_crit_sect);
}

leaks::~leaks()
{
    m_inst = 0;
    DeleteCriticalSection(&m_crit_sect);
}

