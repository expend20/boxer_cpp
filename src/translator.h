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
    bool debug = false;
    bool disasm = false;
    bool single_step = false;
    bool call_to_jmp = false;
    bool cmpcov = false;
    mem_tool* shadow_code = 0;
    int32_t red_zone_size = 0;
};

struct translator_stats {
    size_t cmpcov_cmp = 0;
    size_t cmpcov_sub = 0;
    size_t cmpcov_test = 0;
    size_t translated_bbs = 0;
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
        size_t translate(size_t addr, uint32_t* instrumented_size, 
                uint32_t* original_size);

        uint32_t make_jump_from_orig_to_inst(size_t jump_from, size_t jump_to);
        uint32_t make_1byte_jump_from_orig_to_orig( size_t jump_from, 
                size_t jump_to);
        void fix_dd_refs();

        void set_debug() { m_opts.debug = true; };
        void set_disasm() { m_opts.disasm = true; };
        void set_single_step() { m_opts.single_step = true; };
        void set_call_to_jump() { m_opts.call_to_jmp = true; };
        void set_cmpcov() { m_opts.cmpcov = true; };
        void set_shadow_code(mem_tool* p) { m_opts.shadow_code = p; };
        void set_bbs(std::set<size_t>* p) { m_bbs = p; };

        translator_stats* get_stats() { return &m_stats; };
        uint32_t get_cmpinst_size() { return m_cmpcov_offset; };

    private:
        uint8_t* get_inst_ptr();
        uint32_t get_inst_bytes_left();

        void adjust_inst_offset(size_t v);
        void adjust_cov_offset(size_t v);
        void adjust_cmpcov_offset(size_t v);

        void adjust_stack_red_zone();
        void adjust_stack_red_zone_back();
        void adjust_stack(int32_t sp_offset);

        void make_pushf();
        void make_popf();
        void make_dword_inc_cov_hit();
        void make_dword_mov_cov_hit();

        void make_jump_to_orig_or_inst(size_t target_addr);

        uint32_t translate_call_to_jump(
                dasm::opcode* op, uint8_t* buf, uint32_t buf_size, 
                size_t target_addr);

        void add_cmpcov_inst(size_t addr, dasm::opcode* op);
        bool is_target_8bits(dasm::opcode* op);

        uint32_t make_op_1(xed_iclass_enum_t iclass, uint32_t bits, 
                xed_encoder_operand_t op);

        uint32_t make_op_2(xed_iclass_enum_t iclass, uint32_t bits, 
                xed_encoder_operand_t op1, xed_encoder_operand_t op2);

    private:
        mem_tool*         m_inst_code = NULL;
        mem_tool*         m_cov_buf = NULL;
        mem_tool*         m_cmpcov_buf = NULL;
        mem_tool*         m_text_sect = NULL;

        size_t            m_inst_offset = 0;
        size_t            m_cov_offset = 0;
        size_t            m_cmpcov_offset = 0;
        size_t            m_text_sect_remote_addr = 0;

        std::set<size_t>* m_bbs = 0;

        dasm::cached_code m_dasm_cache;
        translator_opts   m_opts;
        translator_stats  m_stats;

        // Remote origin RIP to remote instrumented code
        std::map<size_t, size_t> m_remote_orig_to_inst_bb;
        std::set<size_t> m_remote_dd_refs;

};
