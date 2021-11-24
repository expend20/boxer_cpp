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
    size_t bb_skipped = 0;
};

struct instrumenter_options {
    bool is_int3_inst_blind = false;
    bool is_bbs_inst = false;
    bool is_bbs_inst_all = false;
    bool call_to_jump = false;
    const char* bbs_path = 0;
    bool fix_dd_refs = false;
    bool debug = false;
    bool skip_small_bb = false;
    bool show_flow = false;
    bool translator_debug = false;
    bool translator_disasm = false;
    bool translator_single_step = false;
    size_t stop_at = 0;
};

struct instrumenter_module_data {
    std::string module_name;
    mem_tool    shadow;
    mem_tool    inst;
    mem_tool    cov;
    mem_tool    metadata;
    translator  translator;
};

class instrumenter: public idebug_handler {

    public:
        instrumenter() {};
        DWORD handle_debug_event(DEBUG_EVENT* dbg_event,
                debugger* debuger) override;
        void add_module(const char* module);
        void print_stats();

        // opts setters
        void set_int3_inst_blind() { m_opts.is_int3_inst_blind = true; };
        void set_bbs_inst() { m_opts.is_bbs_inst = true; };
        void set_bbs_inst_all() { m_opts.is_bbs_inst_all = true; };
        void set_bbs_path(const char* p) { m_opts.bbs_path = p; };
        void set_fix_dd_refs() { m_opts.fix_dd_refs = true; };
        void set_debug() { m_opts.debug = true; };
        void set_show_flow() { m_opts.show_flow = true; };
        void set_trans_debug() { m_opts.translator_debug = true; };
        void set_trans_disasm() { m_opts.translator_disasm = true; };
        void set_trans_single_step() { m_opts.translator_single_step = true; };
        void set_call_to_jump() { m_opts.call_to_jump = true; };
        void set_skip_small_bb() { m_opts.skip_small_bb = true; };
        void set_stop_at(size_t v) { m_opts.stop_at = v; };

    private:

        DWORD handle_exception(EXCEPTION_DEBUG_INFO* dbg_info);
        void on_first_breakpoint();
        bool should_instrument_module(const char* name);
        void instrument_module(size_t addr, const char* name);
        void instrument_module_int3(size_t addr, const char* name);
        bool should_translate(size_t addr);
        void translate_all_bbs();
        void patch_references_to_section(pehelper::pe* module, 
                pehelper::section* target_section, 
                size_t shadow_sect_remote_start);

    private:
        instrumenter_stats m_stats = {0};
        debugger* m_debugger = NULL;
        DEBUG_EVENT* m_dbg_event = NULL;
        bool m_first_breakpoint_reached = false;

        std::vector<std::string> m_modules_to_instrument;
        std::vector<pehelper::pe> m_modules;
        std::vector<pehelper::section*> m_sections_patched;
        std::map<size_t, size_t> m_sect_base_to_module;

        std::map<size_t, instrumenter_module_data> m_base_to;
        std::map<DWORD, HANDLE> m_tid_to_handle;

        std::set<size_t> m_bbs;

        instrumenter_options m_opts;

};

#endif // INSTRUMENTOR_H
