#ifndef INSTRUMENTER_H
#define INSTRUMENTER_H

#include "debugger.h"
#include "veh.h"
#include "pe.h"
#include "translator.h"
#include "strcov.h"
#include "leaks.h"

#include <map>
#include <string>
#include <vector>

#define MARKER_STORE_CONTEXT (0x1337 + 0)
#define MARKER_RESTORE_CONTINUE (0x1337 + 1)


struct instrumenter_bb_info {
    uint32_t orig_size = 0;
    uint32_t bytes_taken = 0;
};

struct instrumenter_stats {
    size_t dbg_callbacks = 0;
    size_t veh_callbacks = 0;
    size_t exceptions = 0;
    size_t breakpoints = 0;
    size_t cpp_exceptions = 0;
    size_t output_debug_str = 0;
    size_t avs = 0;
    size_t rip_redirections = 0;
    size_t bb_skipped_less_5 = 0;
    size_t bb_skipped_less_2 = 0;
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
    bool translator_cmpcov = false;
    size_t stop_at = 0;
    size_t covbuf_size = 64 * 1024;
};

struct crash_info {
    uint32_t code = 0;
    size_t offset = 0;
    std::string mod_name;
};

class instrumenter_module_data {
    public:
        std::string        module_name;
        pehelper::pe       pe;
        pehelper::section* code_sect;
        mem_tool           shadow;
        mem_tool           inst;
        mem_tool           cov;
        mem_tool           cmpcov;
        translator         translator;
    private:
        //instrumenter_module_data(const instrumenter_module_data&) = delete;
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
        instrumenter_stats* get_stats() { return &m_stats; };
        crash_info* get_crash_info() { return &m_crash_info; };
        void clear_crash_info() { m_crash_info = {0}; };

        // opts setters
        void set_int3_inst_blind() { m_opts.is_int3_inst_blind = true; };
        void set_bbs_inst() { m_opts.is_bbs_inst = true; };
        void set_bbs_inst_all() { m_opts.is_bbs_inst_all = true; };
        void set_bbs_path(const char* p) { m_opts.bbs_path = p; };
        void set_fix_dd_refs() { m_opts.fix_dd_refs = true; };
        void set_debug() { m_opts.debug = true; };
        void set_show_flow() { m_opts.show_flow = true; };
        void set_trans_cmpcov() { m_opts.translator_cmpcov = true; };
        void set_trans_debug() { m_opts.translator_debug = true; };
        void set_trans_disasm() { m_opts.translator_disasm = true; };
        void set_trans_single_step() { m_opts.translator_single_step = true; };
        void set_call_to_jump() { m_opts.call_to_jump = true; };
        void set_skip_small_bb() { m_opts.skip_small_bb = true; };
        void set_stop_at(size_t v) { m_opts.stop_at = v; };
        void set_covbuf_size(size_t v) { m_opts.covbuf_size = v; };

        void install_strcmpcov();
        void uninstall_strcmpcov();
        void install_leaks();
        void uninstall_leaks();

        uint8_t* get_cov(uint32_t* size);
        uint8_t* get_cmpcov(uint32_t* size);
        CONTEXT* get_restore_ctx() { return &m_restore_ctx; };
        void adjust_restore_context();
        std::vector<strcmp_data>* get_strcmpcov();

        void clear_cov();
        void clear_cmpcov();
        void clear_strcmpcov();
        void clear_leaks();

    private:
        //instrumenter(const instrumenter&) = delete;

        void handle_crash(uint32_t code, size_t addr);
        DWORD handle_exception(EXCEPTION_DEBUG_INFO* dbg_info);
        bool should_instrument_module(const char* name);
        void instrument_module(size_t addr, const char* name);
        bool translate_or_redirect(size_t addr);
        void translate_all_bbs();
        void on_first_breakpoint();
        HANDLE get_target_process();
        void redirect_execution(size_t addr, size_t addr_inst);
        size_t find_inst_module(size_t addr);
        size_t find_inst_module_by_inst_addr(size_t addr);
        void fix_two_bytes_bbs(translator* trans, 
                std::map<size_t, instrumenter_bb_info>* bbs_info, 
                std::vector<size_t>* two_bytes_bbs);


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
        CONTEXT m_restore_ctx = {0};
        strcmpcov m_strcmpcov;
        leaks m_leaks;
        crash_info m_crash_info;

        uint32_t m_pc_restore_offset = 0;
};

#endif // INSTRUMENTER_H
