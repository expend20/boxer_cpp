#include "translator.h"
#include "Say.h"

size_t translator::instrument(size_t addr)
{
    // should instrument instruction

    // disassemble 

    // modify one instruction 
    // mark jump

    // assemble again
    return 0x123123123;
}

translator::translator(
        mem_tool* inst_code, 
        mem_tool* cov_buf, 
        mem_tool* metadata):
    m_inst_code(inst_code),
    m_cov_buf(cov_buf),
    m_metadata(metadata) 
{
    ASSERT(m_inst_code);
    ASSERT(m_cov_buf);
    ASSERT(m_metadata);
}

size_t translator::remote_to_inst(size_t addr) {
    return m_remote_to_inst.find(addr) == m_remote_to_inst.end() ?
        0 : 
        m_remote_to_inst[addr];
}
