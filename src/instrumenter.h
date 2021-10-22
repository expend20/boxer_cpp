#ifndef INSTRUMENTOR_H
#define INSTRUMENTOR_H

#include "debugger.h"
#include "pe.h"

#include <map>
#include <string>
#include <vector>

struct instrumentor_stats {
    size_t dbg_callbaks;
    size_t exceptions;
    size_t breakpoints;
    size_t avs;
};

class instrumenter: public idebug_handler {

    public:
        instrumenter() {};
        DWORD handle_debug_event(DEBUG_EVENT* dbg_event,
                debugger* debuger) override;
        void add_module(const char* module);

    private:

        DWORD handle_exception(EXCEPTION_DEBUG_INFO* dbg_info);
        void on_first_breakpoint();
        void should_instrument_modules();
        void instrument_module(size_t addr, const char* name);
        bool should_handle_dep_av(size_t addr);

    private:
        instrumentor_stats m_stats = {0};
        std::map<size_t, std::string> m_remote_modules_list;
        std::vector<std::string> m_modules_to_instrument;
        std::vector<pehelper::pe> m_modules;
        std::vector<pehelper::section*> m_sections_patched;
        debugger* m_debugger = NULL;

};

#endif // INSTRUMENTOR_H
