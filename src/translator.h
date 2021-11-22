/* The purpose of this code translator is quite narrow. It's is not supposed to
 * instrument all the code, but only those which got execution.
 * When we disassemble the code, we mark each JXX to destinguish if they were 
 * hit. Those branch which were not hit, will never be instrumented. Hope this
 * makes sense.
 * Another goal of this translator is to emit instrumentation which would be
 * persistant between restarts.
 * Other aspects like instrumenteation and cmpcov shold be implemented too.
 */

#include "mem_tool.h"
#include "dasm.h"
#include <map>
#include <set>

struct translator_opts {
    bool fix_dd_refs = false;
    bool debug = false;
    bool disasm = false;
    bool single_step = false;
    bool call_to_jmp = false;
    mem_tool* shadow_code = 0;
};

class translator {

    public:
        translator(){};
        
        translator(mem_tool* inst_code, 
                mem_tool* cov_buf, 
                mem_tool* metadata,
                mem_tool* text_sect,
                size_t text_sect_remote_addr);

        size_t remote_orig_to_inst_bb(size_t addr);
        size_t instrument(size_t addr, uint32_t* instrumented_size, 
                uint32_t* original_size);

        void make_dword_inc_cov_hit();
        void make_dword_mov_cov_hit();
        void make_jump_to_orig_or_inst(size_t target_addr);
        uint32_t make_jump_from_orig_to_inst(size_t jump_from, size_t jump_to);
        uint32_t translate_call_to_jump(
                dasm::opcode* op, uint8_t* buf, size_t buf_size, 
                size_t target_addr);

        void set_fix_dd_refs() { m_opts.fix_dd_refs = true; };
        void set_debug() { m_opts.debug = true; };
        void set_disasm() { m_opts.disasm = true; };
        void set_single_step() { m_opts.single_step = true; };
        void set_call_to_jump() { m_opts.call_to_jmp = true; };
        void set_shadow_code(mem_tool* p) { m_opts.shadow_code = p; };
        void set_bbs(std::set<size_t>* p) { m_bbs = p; };

    private:
        mem_tool*         m_inst_code = NULL;
        mem_tool*         m_cov_buf = NULL;
        mem_tool*         m_metadata = NULL;
        mem_tool*         m_text_sect = NULL;
        size_t            m_inst_offset = 0;
        size_t            m_cov_offset = 0;
        size_t            m_text_sect_remote_addr = 0;
        std::set<size_t>* m_bbs = 0;

        dasm::cached_code m_dasm_cache;
        translator_opts   m_opts;

        // Remote origin RIP to remote instrumented code
        std::map<size_t, size_t> m_remote_orig_to_inst_bb;
        std::set<size_t> m_remote_dd_refs;

        void fix_dd_refs();

};
