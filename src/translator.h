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

class translator {

    public:

        mem_tool*         m_inst_code = NULL;
        mem_tool*         m_cov_buf = NULL;
        mem_tool*         m_metadata = NULL;
        mem_tool*         m_text_sect = NULL;
        size_t            m_inst_offset = 0;
        size_t            m_cov_offset = 0;
        dasm::cached_code m_dasm_cache;

        // Remote origin RIP to remote instrumented code
        std::map<size_t, size_t> m_remote_orig_to_inst_bb;
        std::set<size_t> m_remote_dd_refs;

    public:

        translator(){};
        
        translator(mem_tool* inst_code, 
                mem_tool* cov_buf, 
                mem_tool* metadata,
                mem_tool* text_sect);

        size_t remote_orig_to_inst_bb(size_t addr);
        size_t instrument(size_t addr);

        void make_dword_inc_cov_hit();
        void make_jump(size_t target_addr);
        void fix_dd_refs();
};
