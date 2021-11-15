#include "translator.h"
#include "Say.h"
#include "dasm.h"


void translator::make_dword_mov_cov_hit()
{
    size_t inst_size = 6;
    ASSERT(m_inst_offset + inst_size < m_inst_code->size());
    ASSERT(m_cov_offset + 4 < m_cov_buf->size());

    size_t bits = 32;
    auto op = dasm::maker();
#ifdef _WIN64
    size_t disp = (m_cov_buf->addr_remote() + m_cov_offset)
        - (m_inst_code->addr_remote() + m_inst_offset + inst_size);
    xed_inst2(&op.enc_inst, op.dstate,
            XED_ICLASS_MOV, 0,
            xed_mem_bd(XED_REG_RIP, xed_disp(disp, bits), bits),
            xed_imm0(1, bits)
            );
#else 
    size_t disp = m_cov_buf->addr_remote() + m_cov_offset;
    xed_inst2(&op.enc_inst, op.dstate,
            XED_ICLASS_MOV, 0,
            xed_mem_bd(XED_REG_INVALID, xed_disp(disp, bits), bits),
            xed_imm0(1, bits)
            );
#endif
    auto new_inst_size = op.make(
            (uint8_t*)(m_inst_code->addr_loc() + m_inst_offset), 
            inst_size);
    ASSERT(new_inst_size == inst_size);
    m_cov_offset += 4;
    m_inst_offset += new_inst_size;
}

void translator::make_dword_inc_cov_hit()
{
    size_t inst_size = 7;
    ASSERT(m_inst_offset + inst_size < m_inst_code->size());
    ASSERT(m_cov_offset + 4 < m_cov_buf->size());

    size_t bits = 32;
    auto op = dasm::maker();
#ifdef _WIN64
    size_t disp = (m_cov_buf->addr_remote() + m_cov_offset)
        - (m_inst_code->addr_remote() + m_inst_offset + inst_size);
    xed_inst2(&op.enc_inst, op.dstate,
            XED_ICLASS_ADD, 0,
            xed_mem_bd(XED_REG_RIP, xed_disp(disp, bits), bits),
            xed_imm0(1, 8)
            );
#else 
    size_t disp = m_cov_buf->addr_remote() + m_cov_offset;
    xed_inst2(&op.enc_inst, op.dstate,
            XED_ICLASS_ADD, 0,
            xed_mem_bd(XED_REG_INVALID, xed_disp(disp, bits), bits),
            xed_imm0(1, 8)
            );
#endif
    auto new_inst_size = op.make(
            (uint8_t*)(m_inst_code->addr_loc() + m_inst_offset), 
            inst_size);
    ASSERT(new_inst_size == inst_size);
    m_cov_offset += 4;
    m_inst_offset += new_inst_size;
}

void translator::make_jump(size_t target_addr)
{
    auto already_inst = remote_orig_to_inst_bb(target_addr);
    if (already_inst) target_addr = already_inst;

    size_t inst_size = 5;
    ASSERT(m_inst_offset + inst_size < m_inst_code->size());

    size_t bits = 32;
    size_t disp = target_addr 
        - (m_inst_code->addr_remote() + m_inst_offset + inst_size);
    auto op = dasm::maker();
    xed_inst1(&op.enc_inst, op.dstate,
            XED_ICLASS_JMP, 32,
            xed_relbr(disp, 32));
    auto new_inst_size = op.make(
            (uint8_t*)(m_inst_code->addr_loc() + m_inst_offset), 
            inst_size);
    ASSERT(new_inst_size == inst_size);
    m_inst_offset += new_inst_size;
}

void translator::fix_dd_refs() {
    for (auto &remote_ptr: m_remote_dd_refs) {
        auto offset = remote_ptr - m_inst_code->addr_remote();
        auto loc_ptr = m_inst_code->addr_loc() + offset;
        auto disp = *(int32_t*)loc_ptr;
        auto next_remote = offset + 4 + m_inst_code->addr_remote();
        auto tgt_ref = disp + next_remote;
        auto inst_addr = remote_orig_to_inst_bb(tgt_ref);
        if (inst_addr) {
            SAY_DEBUG("fixing dd ref at (next) %p to %p -> %p...\n", 
                    next_remote, tgt_ref, inst_addr);
            uint32_t new_dd = inst_addr - next_remote;
            *(uint32_t*)loc_ptr = new_dd;
            m_remote_dd_refs.erase(remote_ptr);
        }
    }
}

// Here we do quite simple instrumentation. We instrument only one basic block
// from the perspective of current pointer, meaning if then discovered jump to
// the middle of existing basic block, we will create new one with partial code
// duplication. We also do not follow any references in advance. 
// This strategy leads to the instrumentation of only code wich is hit.
size_t translator::instrument(size_t addr)
{
    static auto one_time_init = false;
    if (!one_time_init) {
        xed_tables_init();
        one_time_init = true;
    }

    auto rip = addr;
    size_t bb_start = 0;
    while(1) {
        auto remote_inst = m_inst_code->addr_remote() + m_inst_offset;
        // should instrument instruction
        if (!bb_start) {
            bb_start = remote_inst;
            m_remote_orig_to_inst_bb[rip] = remote_inst;
            SAY_DEBUG("remote bb got instrumented %p -> %p\n", 
                    rip, remote_inst);
            //make_dword_inc_cov_hit();
            //make_dword_mov_cov_hit();
            remote_inst = m_inst_code->addr_remote() + m_inst_offset;
        }

        // disasm & cache
        auto offset = rip - m_text_sect_remote_addr;
        auto local_addr = m_text_sect->addr_loc() + offset;
        SAY_DEBUG("Disasm (%x) local: %p remote: %p text sect remote: %p\n", 
                offset, local_addr, rip, m_text_sect_remote_addr);
        auto op = m_dasm_cache.get(local_addr, rip, m_text_sect_remote_addr,
                m_text_sect->addr_remote(), m_text_sect->size());

        // TODO: debug code only
        {
            char buf[128];
            auto r = xed_format_context(XED_SYNTAX_INTEL, 
                    &op->xedd,
                    buf,
                    sizeof(buf), 0, 0, 0);
            SAY_DEBUG("%p %p %-30s (Category: %s, iclass: %s)\n",
                    rip, 
                    remote_inst,
                    buf,
                    xed_category_enum_t2str(op->category),
                    xed_iclass_enum_t2str(op->iclass));
        }

        auto inst_sz = op->rebuild_to_new_addr(
                (uint8_t*)m_inst_code->addr_loc() + m_inst_offset,
                m_inst_code->addr_loc_end() - local_addr,
                remote_inst);
        ASSERT(inst_sz);
        m_inst_offset += inst_sz;

        if (op->branch_disp_width) {
            // keep track of jumps, while them are not poiting to the 
            // instrumented code
            m_remote_dd_refs.insert(
                    m_inst_code->addr_remote() + m_inst_offset - 4);
        }

        if (op->category == XED_CATEGORY_RET) {
            break;
        }
        if (op->iclass == XED_ICLASS_JMP) {
            break;
        }
        if (op->iclass == XED_ICLASS_INT3) {
            break;
        }
        if (op->is_iclass_jxx() 
                //|| op->category == XED_CATEGORY_CALL
                ) {
            // place new jump to keep code valid
            auto tgt_addr = op->size_orig + op->addr;
            make_jump(tgt_addr);
            m_remote_dd_refs.insert(
                    m_inst_code->addr_remote() + m_inst_offset - 4);
            break;
        }

        // continue the loop
        rip += op->size_orig;
    }
    fix_dd_refs();
    m_inst_code->commit();

    return m_remote_orig_to_inst_bb[addr];
}

translator::translator(mem_tool* inst_code, 
        mem_tool* cov_buf, 
        mem_tool* metadata,
        mem_tool* text_sect,
        size_t text_sect_remote_addr):
    m_inst_code(inst_code),
    m_cov_buf(cov_buf),
    m_metadata(metadata),
    m_text_sect(text_sect),
    m_text_sect_remote_addr(text_sect_remote_addr)
{
    ASSERT(m_inst_code);
    ASSERT(m_cov_buf);
    ASSERT(m_metadata);
    ASSERT(m_text_sect);
}

size_t translator::remote_orig_to_inst_bb(size_t addr) {
    return m_remote_orig_to_inst_bb.find(addr) == 
        m_remote_orig_to_inst_bb.end() ?
        0 : 
        m_remote_orig_to_inst_bb[addr];
}
