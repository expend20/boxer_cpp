#ifndef INSTRUMENTOR_H
#define INSTRUMENTOR_H

#include "debugger.h"
#include "pe.h"
#include "translator.h"

#include <map>
#include <string>
#include <vector>

struct instrumenter_stats {
    size_t dbg_callbaks = 0;
    size_t exceptions = 0;
    size_t breakpoints = 0;
    size_t avs = 0;
    size_t translator_called = 0;
    size_t rip_redirections = 0;
};

struct instrumenter_options {
    bool is_int3_inst = false;
    bool fix_dd_refs = false;
    bool debug = false;
    bool show_flow = false;
    bool translator_debug = false;
    bool translator_disasm = false;
    bool translator_single_step = false;
};

class instrumenter: public idebug_handler {

    public:
        instrumenter() {};
        DWORD handle_debug_event(DEBUG_EVENT* dbg_event,
                debugger* debuger) override;
        void add_module(const char* module);
        void print_stats();

        // opts setter
        void set_int3_inst() { m_opts.is_int3_inst = true; };
        void set_fix_dd_refs() { m_opts.fix_dd_refs = true; };
        void set_debug() { m_opts.debug = true; };
        void set_show_flow() { m_opts.show_flow = true; };
        void set_trans_debug() { m_opts.translator_debug = true; };
        void set_trans_disasm() { m_opts.translator_disasm = true; };
        void set_trans_single_step() { m_opts.translator_single_step = true; };

    private:

        DWORD handle_exception(EXCEPTION_DEBUG_INFO* dbg_info);
        void on_first_breakpoint();
        bool should_instrument_module(const char* name);
        void instrument_module(size_t addr, const char* name);
        void instrument_module_int3(size_t addr, const char* name);
        bool should_translate(size_t addr);
        void patch_references_to_section(pehelper::pe* module, 
                pehelper::section* target_section, 
                size_t shadow_sect_remote_start);

    private:
        instrumenter_stats m_stats = {0};
        debugger* m_debugger = NULL;
        DEBUG_EVENT* m_dbg_event = NULL;

        std::vector<std::string> m_modules_to_instrument;
        std::vector<pehelper::pe> m_modules;
        std::vector<pehelper::section*> m_sections_patched;
        std::map<size_t, size_t> m_sect_base_to_module;

        // TODO: refactor all base_to* to one map with struct perhaps?
        std::map<size_t, std::string> m_remote_modules_list;
        std::map<size_t, mem_tool> m_base_to_shadow;
        std::map<size_t, mem_tool> m_base_to_inst;
        std::map<size_t, mem_tool> m_base_to_cov;
        std::map<size_t, mem_tool> m_base_to_metadata;
        std::map<size_t, translator> m_base_to_translator;

        std::map<DWORD, HANDLE> m_tid_to_handle;

        instrumenter_options m_opts;

};

#endif // INSTRUMENTOR_H
