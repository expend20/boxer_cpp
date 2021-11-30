#ifndef INSTRUMENTOR_H
#define INSTRUMENTOR_H

#include "debugger.h"
#include "veh.h"
#include "pe.h"
#include "translator.h"

#include <map>
#include <string>
#include <vector>

struct instrumenter_stats {
    size_t dbg_callbacks = 0;
    size_t veh_callbacks = 0;
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
    std::string        module_name;
    pehelper::pe       pe;
    pehelper::section* code_sect;
    mem_tool           shadow;
    mem_tool           inst;
    mem_tool           cov;
    mem_tool           cmpcov;
    translator         translator;
};

class instrumenter: public idebug_handler, public iveh_handler {

    public:
        instrumenter();
        ~instrumenter();

        DWORD handle_debug_event(DEBUG_EVENT* dbg_event,
                debugger* debuger) override;
        DWORD handle_veh(_EXCEPTION_POINTERS* ex_info) override;

        void add_module(const char* module);

        void explicit_instrument_module(size_t addr, const char* name);

        void uninstrument(size_t addr);
        void uninstrument_all();

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
        bool should_instrument_module(const char* name);
        void instrument_module(size_t addr, const char* name);
        bool translate_or_redirect(size_t addr);
        void translate_all_bbs();
        void on_first_breakpoint();
        HANDLE get_target_process();
        void redirect_execution(size_t addr, size_t addr_inst);
        size_t find_inst_module(size_t addr);

    private:
        instrumenter_stats m_stats = {0};
        instrumenter_options m_opts;

        std::map<size_t, instrumenter_module_data> m_inst_mods;

        std::set<size_t> m_bbs;

        // valid only for debugger backend
        std::vector<std::string> m_modules_to_instrument;
        std::map<size_t, std::string> m_loaded_mods;
        debugger* m_debugger = NULL;
        DEBUG_EVENT* m_dbg_event = NULL;
        bool m_first_breakpoint_reached = false;
        std::map<DWORD, HANDLE> m_tid_to_handle;

        // valid only for VEH backend
        CONTEXT* m_ctx = NULL;

};

#endif // INSTRUMENTOR_H
