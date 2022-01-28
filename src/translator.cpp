#include "translator.h"
#include "say.h"
#include "dasm.h"

#define PS sizeof(size_t) // pointer's size

#ifdef _WIN64

#define XED_REG_PC XED_REG_RIP
#define XED_REG_PC_INVALID XED_REG_RIP
#define XED_REG_SP XED_REG_RSP
#define X64_OR_X86(val64, val32) (val64)

#else

#define XED_REG_PC XED_REG_EIP
#define XED_REG_PC_INVALID XED_REG_INVALID
#define XED_REG_SP XED_REG_ESP
#define X64_OR_X86(val64, val32) (val32)

#endif

class reg_tool {
public:

    xed_reg_enum_t first = XED_REG_INVALID;
    xed_reg_enum_t second = XED_REG_INVALID;
    xed_reg_enum_t first_s = XED_REG_INVALID;
    xed_reg_enum_t second_s = XED_REG_INVALID;

    reg_tool(dasm::opcode* op) {
        init_from_op(op);
    }

    xed_reg_enum_t allocate_new() {
        auto r = allocate_new_except(XED_REG_INVALID);
        m_spoiled_to_orig[r] = XED_REG_INVALID;
        return r;
    }

    void set_first(xed_reg_enum_t v) {
        // check in spoiled first
        for (auto const& [sp, orig]: m_spoiled_to_orig) {
            if (orig == v) {
                first = sp;
                return;
            }
        }
        first = v;
    }

    void set_second(xed_reg_enum_t v) {
        // check in spoiled first
        for (auto const& [sp, orig]: m_spoiled_to_orig) {
            if (orig == v) {
                second = sp;
                return;
            }
        }
        second = v;
    }

    void update_smallest() {
        first_s = dasm::opcode::get_reg_from_largest(first, 8);
        second_s = dasm::opcode::get_reg_from_largest(second, 8);
    }

    std::vector<xed_reg_enum_t> get_spoiled() {
        std::vector<xed_reg_enum_t> r;
        for (auto const& [sp, orig]: m_spoiled_to_orig) {
            r.push_back(sp);
        }
        return std::move(r);
    }

    std::vector<std::pair<xed_reg_enum_t, xed_reg_enum_t>> get_moved() {
        std::vector<std::pair<xed_reg_enum_t, xed_reg_enum_t>> r;
        for (auto const& [sp, orig]: m_spoiled_to_orig) {
            if (orig != XED_REG_INVALID) {
                r.push_back(std::make_pair(sp, orig));
            }
        }
        return std::move(r);
    }


private:

    xed_reg_enum_t allocate_new_except(xed_reg_enum_t cur_reg) {
        // make temp list
        //std::vector<xed_reg_enum_t> new_vec;
        auto new_vec = m_preserved;
        for (auto const& [sp, orig]: m_spoiled_to_orig) {
            new_vec.push_back(sp);
            new_vec.push_back(orig);
        }
        new_vec.push_back(cur_reg);
        ASSERT(new_vec.size() != m_preserved.size());

        // req new
        auto new_largest = dasm::opcode::get_reg_except_this_list(
                &new_vec[0], new_vec.size());
        return new_largest;
    }


    void init_from_op(dasm::opcode* op) {

        if (op->reg_base != XED_REG_INVALID) {
            auto r = dasm::opcode::get_largest(op->reg_base);
            m_preserved.push_back(r);
        }
        if ( op->reg_index != XED_REG_INVALID) {
            auto r = dasm::opcode::get_largest(op->reg_index);
            m_preserved.push_back(r);
        }

        first = op->reg0_largest;
        second = op->reg1_largest;

        xed_reg_enum_t largest_regs[] = {first, second};
        xed_reg_enum_t disallowed_regs[] = {XED_REG_RSI, XED_REG_RDI, 
            XED_REG_RBP, XED_REG_RSP};

        for (auto cur_reg: largest_regs) {
            bool matched = false;
            for (auto disallowed_reg: disallowed_regs) {
                if (cur_reg == disallowed_reg) {
                    matched = true;
                }
            }
            if (matched) {
                auto new_largest = allocate_new_except(cur_reg);

                // update state
                m_spoiled_to_orig[new_largest] = cur_reg;

                if (cur_reg == first) {
                    first = new_largest;
                }
                else if (cur_reg == second) {
                    second = new_largest;
                }
            }
            else {
                // just spoil without orig
                if (cur_reg != XED_REG_RFLAGS &&
                        cur_reg != XED_REG_INVALID) {
                    m_spoiled_to_orig[cur_reg] = XED_REG_INVALID;
                }
            }
        }
    }

private:

    std::map<xed_reg_enum_t, xed_reg_enum_t> m_spoiled_to_orig;
    std::vector<xed_reg_enum_t> m_preserved;
};

uint32_t translator::make_op_1(xed_iclass_enum_t iclass, uint32_t bits, 
        xed_encoder_operand_t op)
{
    auto new_op = dasm::maker();
    xed_inst1(&new_op.enc_inst, new_op.dstate,
            iclass, bits, op);                                    
    auto sz = new_op.make(get_inst_ptr(), get_inst_bytes_left()); 
    adjust_inst_offset(sz);                                   
    return sz;
}

uint32_t translator::make_op_2(xed_iclass_enum_t iclass, uint32_t bits, 
        xed_encoder_operand_t op1, xed_encoder_operand_t op2)
{
    auto new_op = dasm::maker();
    xed_inst2(&new_op.enc_inst, new_op.dstate,
            iclass, bits, op1, op2);
    auto sz = new_op.make(get_inst_ptr(), get_inst_bytes_left()); 
    adjust_inst_offset(sz);
    return sz;
}

bool translator::is_target_le_8bits(dasm::opcode* op) 
{
    auto res = false;

    if (op->imm_width <= 8 && op->mem_len0 <= 8 && op->op_width <= 8) {
        res = true;
    }
    return res;
}

uint32_t translator::cmp_create_loop(CmpType ty, size_t addr, dasm::opcode* op)
{
    uint32_t jnz_sz = 6;
    uint32_t shr_reg_sz = X64_OR_X86(4, 3);
    uint32_t loop_len = op->op_width / 8;
    uint32_t or_sz = 7;

    bool is_reg_eq = op->reg0 == op->reg1; // cmp rax, rax 

    // NOTE: there is no way to access SIL, DIL, BPL and SPL on x86 (it's 
    // x64 only), so we need to swap them with al, bl, cl or dl.
    auto rt = reg_tool(op);
    
    // introduce temporary registers
    if (ty == MemImm) {
        auto r = rt.allocate_new();
        rt.set_first(r);
    }
    else if (ty == MemReg) {
        auto r = rt.allocate_new();
        rt.set_first(r);
        rt.set_second(op->reg0_largest);
    }

    // store registers
    auto spoiled_regs = rt.get_spoiled();
    for (auto& r: spoiled_regs) {
        make_op_1(XED_ICLASS_PUSH, 64, xed_reg(r));
    }

    // mov registers, if needed
    for (auto& [sp, orig]: rt.get_moved()) {
        make_op_2(XED_ICLASS_MOV, 64, xed_reg(sp), xed_reg(orig));
    }

    uint32_t pushed_size = spoiled_regs.size() * sizeof(size_t);
    rt.update_smallest();

    switch (ty) {
        case MemImm:
        case MemReg:

            uint32_t mem_disp = op->mem_disp;
            uint32_t mem_disp_width = 32; // force disp width to ensure we'll fit
            if (op->reg_base == XED_REG_SP) {
                mem_disp += pushed_size;
            }

            // just get size in PC case
            auto inst_offset_bak = m_inst_offset;
            auto r = dasm::opcode::get_reg_from_largest(rt.first, op->op_width);
            auto mov_sz = make_op_2(XED_ICLASS_MOV, op->op_width,
                    xed_reg(r), 
                    xed_mem_bisd(op->reg_base, 
                        op->reg_index, 
                        op->scale,
                        xed_disp(mem_disp, mem_disp_width),
                        op->op_width));

            // adjust disp & size in PC case
            if (op->reg_base == XED_REG_RIP ||
                    op->reg_base == XED_REG_EIP) {
                m_inst_offset = inst_offset_bak; // restore pointer
                size_t tgt_addr = addr + op->size_orig + op->mem_disp;
                size_t inst_end = (size_t)m_inst_code->addr_remote() +
                    m_inst_offset + mov_sz;
                mem_disp = tgt_addr - inst_end;
                mov_sz = make_op_2(XED_ICLASS_MOV, op->op_width,
                        xed_reg(r), 
                        xed_mem_bisd(op->reg_base, 
                            op->reg_index, 
                            op->scale,
                            xed_disp(mem_disp, 
                                op->mem_disp_width * 8), 
                            op->op_width));
            }
    }

    bool shift_second_reg = false;
    if ((ty == RegReg && !is_reg_eq) || (ty == MemReg)) {
        shift_second_reg = true;
    }
    // compare each byte
    for (uint32_t i = 0; i < loop_len; i++) {
        // NOTE: signed extension is possible:
        uint8_t curr_cmp_imm = (op->imm >> (i * 8)) & 0xff;

        if (i) {

            auto new_shr_sz = make_op_2(XED_ICLASS_SHR, 64, 
                    xed_reg(rt.first),
                    xed_imm0(8, 8));
            ASSERT(new_shr_sz == shr_reg_sz);

            if (shift_second_reg) {
                new_shr_sz = make_op_2(XED_ICLASS_SHR, 64, 
                        xed_reg(rt.second),
                        xed_imm0(8, 8));
                ASSERT(new_shr_sz == shr_reg_sz);
            }
        }
        // cmp/test reg, imm. Size may vary
        auto cmp_sz = 0;

        switch (ty) {
            case RegImm:
                cmp_sz = make_op_2(op->iclass, 0, 
                        xed_reg(rt.first_s), 
                        xed_imm0(curr_cmp_imm, 8));
                break;
            case RegReg:
            case MemReg:
                cmp_sz = make_op_2(op->iclass, op->op_width, 
                        xed_reg(rt.first_s), 
                        xed_reg(rt.second_s));
                break;

            case MemImm:
                cmp_sz = make_op_2(op->iclass, op->op_width, 
                        xed_reg(rt.first_s), 
                        xed_imm0(curr_cmp_imm, 8));
                break;
        }

        uint32_t full_sz = or_sz + shr_reg_sz + cmp_sz + jnz_sz;
        if (shift_second_reg) {
            full_sz = or_sz + shr_reg_sz * 2 + cmp_sz + jnz_sz;
        }

        uint32_t relbr = 0;
        if (i == loop_len - 1) {
            relbr = or_sz;
        } else {
            relbr = full_sz * (loop_len - (i + 1)) + or_sz;
        }
        uint32_t new_jnz_sz = make_op_1(XED_ICLASS_JNZ, 32, 
                xed_relbr(relbr, 32));
        ASSERT(new_jnz_sz == jnz_sz);

        size_t tgt_addr = m_cmpcov_offset + m_cmpcov_buf->addr_remote();
        size_t inst_end = (size_t)m_inst_code->addr_remote() +
            m_inst_offset + or_sz;
        uint32_t disp = X64_OR_X86(tgt_addr - inst_end, tgt_addr);

        auto new_or_sz = make_op_2(XED_ICLASS_OR, 8, 
                xed_mem_bd(XED_REG_PC_INVALID, xed_disp(disp, 32), 8),
                xed_imm0(1 << i, 8));
        ASSERT(new_or_sz == or_sz);
    }

    // restore registers
    for (auto it = spoiled_regs.rbegin(); it != spoiled_regs.rend(); it++) {
        make_op_1(XED_ICLASS_POP, 64, xed_reg(*it));
    }

    return loop_len;
}

void translator::add_cmpcov_inst(size_t addr, dasm::opcode* op) 
{
    // TODO: if add/sub, shouldn't we compare the result of addition/subraction?

    //SAY_INFO("instrumenting %x cmp %p\n", m_cmpcov_offset, addr);
    auto entry_offset = m_inst_offset;
    auto start_inst_ptr = get_inst_ptr();
    uint32_t loop_len = 0;

    // NOTE: operands order does mater, it sould be `cmp [mem], reg` not 
    // `cmp reg, [mem]`
    ASSERT(op->mem_len1 == 0);

    adjust_stack_red_zone();

    if (op->first_op_name == XED_OPERAND_REG0 &&
            op->second_op_name == XED_OPERAND_IMM0){
        // cmp edx, 0x31333337
        loop_len = cmp_create_loop(CmpType::RegImm, addr, op);
    }
    else if (op->first_op_name == XED_OPERAND_REG0 &&
            op->second_op_name == XED_OPERAND_REG1) {
        // cmp rax, rcx
        loop_len = cmp_create_loop(CmpType::RegReg, addr, op);
    }
    else if (op->first_op_name == XED_OPERAND_MEM0 &&
            op->second_op_name == XED_OPERAND_IMM0){
        // cmp dword ptr [rbx], 0x46464952
        loop_len = cmp_create_loop(CmpType::MemImm, addr, op);
    }
    else if ((op->first_op_name == XED_OPERAND_MEM0 &&
            op->second_op_name == XED_OPERAND_REG0) || 
            (op->first_op_name == XED_OPERAND_REG0 &&
             op->second_op_name == XED_OPERAND_MEM0)){

        // cmp qword ptr [rbx], rdi
        //SAY_INFO("%p\n", get_inst_ptr());
        loop_len = cmp_create_loop(CmpType::MemReg, addr, op);

    }
    else {
        SAY_FATAL("Cmp type not covered ^\n"); exit(-1);
    }
    ASSERT(loop_len);

    adjust_stack_red_zone_back();

    cmpcov_info ci = { (size_t)start_inst_ptr, (size_t)get_inst_ptr(), 
        (1 << loop_len) - 1};
    //SAY_INFO("cmpinfo %x %p %p %x %x\n", m_cmpcov_offset, ci.start, ci.end,
    //        loop_len, ci.all_bits);
    m_cmpcov_info.push_back(ci);

    adjust_cmpcov_offset(1);

    ASSERT(m_inst_offset - entry_offset >= 5); // to place jump
}

void translator::adjust_cmpcov_offset(size_t v)
{
    m_cmpcov_offset += v;
    ASSERT(m_cmpcov_offset <= m_cmpcov_buf->size());
}

void translator::adjust_cov_offset(size_t v)
{
    m_cov_offset += v;
    if (m_cov_offset >= m_cov_buf->size()) {
        ASSERT(m_cov_offset % m_cov_buf->size() == 0);
        m_cov_offset = 0;
        SAY_INFO("Cov buf rounded\n");
    }
}

void translator::adjust_inst_offset(size_t v)
{
    m_inst_offset += v;
    ASSERT(m_inst_offset <= m_inst_code->size());
}

uint8_t* translator::get_inst_ptr()
{
    return (uint8_t*)(m_inst_code->addr_loc_raw() + m_inst_offset);
}

uint32_t translator::get_inst_bytes_left()
{
    return (uint32_t)(m_inst_code->addr_loc_end() - m_inst_offset);
}

void translator::make_dword_mov_cov_hit()
{
    size_t inst_size = 10;

    auto op = dasm::maker();

    size_t disp = (m_cov_buf->addr_remote() + m_cov_offset);
#ifdef _WIN64
    disp -= (m_inst_code->addr_remote() + m_inst_offset + inst_size);
#endif

    xed_inst2(&op.enc_inst, op.dstate,
            XED_ICLASS_MOV, 0,
            xed_mem_bd(XED_REG_PC_INVALID, xed_disp(disp, 32), 32),
            xed_imm0(1, 32)
            );

    auto new_inst_size = op.make(get_inst_ptr(), get_inst_bytes_left());

    ASSERT(new_inst_size == inst_size);
    adjust_cov_offset(4);
    adjust_inst_offset(new_inst_size);
}

void translator::make_pushf()
{
    auto op = dasm::maker();
    xed_inst0(&op.enc_inst, op.dstate, XED_ICLASS_PUSHF, sizeof(size_t)*8);
    auto new_inst_size = op.make(get_inst_ptr(), get_inst_bytes_left());
    adjust_inst_offset(new_inst_size);
}

void translator::make_popf()
{
    auto op = dasm::maker();
    xed_inst0(&op.enc_inst, op.dstate, XED_ICLASS_POPF, sizeof(size_t)*8);
    auto new_inst_size = op.make(get_inst_ptr(), get_inst_bytes_left());
    adjust_inst_offset(new_inst_size);
}

void translator::adjust_stack(int32_t sp_offset) 
{
    make_op_2(XED_ICLASS_LEA, sizeof(size_t) * 8,
            xed_reg(XED_REG_SP),
            xed_mem_bd(XED_REG_SP, xed_disp((uint32_t)sp_offset, 32), 32));

}

void translator::adjust_stack_red_zone() 
{
    if (m_opts.red_zone_size)
        adjust_stack(-m_opts.red_zone_size);
}

void translator::adjust_stack_red_zone_back() 
{
    if (m_opts.red_zone_size)
        adjust_stack(m_opts.red_zone_size);
}

void translator::make_dword_inc_cov_hit()
{
    uint32_t bits = 32;

    adjust_stack_red_zone();
    make_pushf();

    // add dword ptr [addr], 1
    auto op = dasm::maker();
    uint32_t inst_size = 7;

    size_t disp = (m_cov_buf->addr_remote() + m_cov_offset);
#ifdef _WIN64
    disp -= (m_inst_code->addr_remote() + m_inst_offset + inst_size);
#endif
    xed_inst2(&op.enc_inst, op.dstate,
            XED_ICLASS_ADD, 0,
            xed_mem_bd(XED_REG_PC_INVALID, 
                xed_disp((uint32_t)disp, bits), bits),
            xed_imm0(1, 8)
            );

    auto new_inst_size = op.make(get_inst_ptr(), get_inst_bytes_left());
    ASSERT(new_inst_size == inst_size);

    adjust_cov_offset(4);
    adjust_inst_offset(new_inst_size);

    make_popf();
    adjust_stack_red_zone_back();
}

void translator::make_jump_to_orig_or_inst(size_t target_addr)
{
    auto already_inst = remote_orig_to_inst_bb(target_addr);
    if (already_inst) target_addr = already_inst;

    size_t inst_size = 5;

    size_t bits = 32;
    size_t disp = target_addr 
        - (m_inst_code->addr_remote() + m_inst_offset + inst_size);
    auto op = dasm::maker();
    xed_inst1(&op.enc_inst, op.dstate,
            XED_ICLASS_JMP, 32,
            xed_relbr((uint32_t)disp, 32));
    auto new_inst_size = op.make(get_inst_ptr(), get_inst_bytes_left());
    ASSERT(new_inst_size == inst_size);
    adjust_inst_offset(new_inst_size);
}

void translator::fix_dd_refs() {

    std::set<size_t> new_remote_dd_refs;
    for (auto &remote_ptr: m_remote_dd_refs) {
        auto offset = remote_ptr - m_inst_code->addr_remote();
        auto loc_ptr = m_inst_code->addr_loc_raw() + offset;
        auto disp = *(int32_t*)loc_ptr;
        auto next_remote = offset + 4 + m_inst_code->addr_remote();
        auto tgt_ref = disp + next_remote;
        auto inst_addr = remote_orig_to_inst_bb(tgt_ref);
        if (inst_addr) {
            if (m_opts.debug)
                SAY_DEBUG("Fixing dd ref at (next) %p to %p -> %p...\n", 
                        next_remote, tgt_ref, inst_addr);
            size_t new_dd = inst_addr - next_remote;
            *(uint32_t*)loc_ptr = (uint32_t)new_dd;
        }
        else {
            new_remote_dd_refs.insert(remote_ptr);
        }
    }
    m_remote_dd_refs = new_remote_dd_refs;
}

uint32_t translator::translate_call_to_jump(
        dasm::opcode* op, uint8_t* buf, uint32_t buf_size, size_t target_addr)
{
    // let's translate it to `push <orig_addr> & call`
    // make push
    uint32_t inst_size = 0;
    //SAY_DEBUG("Making push... %p %d\n", buf, buf_size);

    // TinyInst's approach:
    // lea     rsp,[rsp-8]
    // mov     dword ptr [rsp],0C6BE108Ch
    // mov     dword ptr [rsp+4],7FF6h
    // jmp     00007ff6`c6bd002c

    // sub rsp, 8
    auto new_op = dasm::maker();
    xed_inst2(&new_op.enc_inst, new_op.dstate,
            XED_ICLASS_SUB, sizeof(size_t) * 8,
            xed_reg(XED_REG_SP),
#ifdef _WIN64
            xed_imm0(8, 8)
#else
            xed_imm0(4, 8)
#endif
            );
    auto new_size = new_op.make(buf, buf_size);
#ifdef _WIN64
    ASSERT(new_size == 4);
#else
    ASSERT(new_size == 3);
#endif
    inst_size += new_size;

    // mov     dword ptr [rsp],0C6BE108Ch
    new_op = dasm::maker();
    xed_inst2(&new_op.enc_inst, new_op.dstate,
            XED_ICLASS_MOV, 0,
            xed_mem_b(XED_REG_SP, 32),
            xed_imm0(target_addr & 0xffffffff, 32)
            );
    new_size = new_op.make(buf + inst_size, buf_size - inst_size);
    ASSERT(new_size == 7);
    inst_size += new_size;

#ifdef _WIN64
    // mov     dword ptr [rsp+4],7FF6h
    new_op = dasm::maker();
    xed_inst2(&new_op.enc_inst, new_op.dstate,
            XED_ICLASS_MOV, 0,
            xed_mem_bd(XED_REG_RSP, xed_disp(4, 8), 32),
            xed_imm0((target_addr >> 32) & 0xffffffff, 32)
            );
    new_size = new_op.make(buf + inst_size, buf_size - inst_size);
    ASSERT(new_size == 8);
    inst_size += new_size;
#endif

    // NOTE: the same code but looks redundant:
    // There is no `push <imm64>` or `mov [rsp], <imm64>` instruction, we can
    // to use register:
    //
    // push rax
    // push rax
    // mov rax, imm64
    // mov [rsp + 8], rax
    // pop rax
    // jmp <call ref>
    //
    //// push rax
    //auto new_op = dasm::maker();
    //xed_inst1(&new_op.enc_inst, new_op.dstate,
    //        XED_ICLASS_PUSH, 64,
    //        xed_reg(XED_REG_RAX));
    //auto new_size = new_op.make(buf, buf_size);
    //ASSERT(new_size == 1);
    //inst_size += new_size;

    //// push rax
    //new_op = dasm::maker();
    //xed_inst1(&new_op.enc_inst, new_op.dstate,
    //        XED_ICLASS_PUSH, 64,
    //        xed_reg(XED_REG_RAX));
    //new_size = new_op.make(buf + inst_size, buf_size - inst_size);
    //ASSERT(new_size == 1);
    //inst_size += new_size;

    //// mov rax, imm64
    //new_op = dasm::maker();
    //xed_inst2(&new_op.enc_inst, new_op.dstate,
    //        XED_ICLASS_MOV, 64,
    //        xed_reg(XED_REG_RAX),
    //        xed_imm0(target_addr, 64));
    //new_size = new_op.make(buf + inst_size, buf_size - inst_size);
    //ASSERT(new_size == 10);
    //inst_size += new_size;

    //// mov [rsp+8], rax
    //new_op = dasm::maker();
    //xed_inst2(&new_op.enc_inst, new_op.dstate,
    //        XED_ICLASS_MOV, 64,
    //        xed_mem_bd(XED_REG_RSP, xed_disp(8, 8), 64),
    //        xed_reg(XED_REG_RAX)
    //        );
    //new_size = new_op.make(buf + inst_size, buf_size - inst_size);
    //ASSERT(new_size == 5);
    //inst_size += new_size;

    //// pop rax
    //new_op = dasm::maker();
    //xed_inst1(&new_op.enc_inst, new_op.dstate,
    //        XED_ICLASS_POP, 64,
    //        xed_reg(XED_REG_RAX));
    //new_size = new_op.make(buf + inst_size, buf_size - inst_size);
    //ASSERT(new_size == 1);
    //inst_size += new_size;

    //ASSERT(inst_size == 18);

    // making jump, get target operand
    auto target_op_name = xed_operand_name(op->first_op);
    if (target_op_name == XED_OPERAND_RELBR) {
        //SAY_DEBUG("XED_OPERAND_RELBR, disp = %x\n",
        //        op->branch_disp);
        uint32_t jmp_size = 5;
        size_t target_branch = target_addr + op->branch_disp;
        size_t inst_end = m_inst_code->addr_remote() + m_inst_offset + 
                inst_size + jmp_size;
        //SAY_DEBUG("target + disp %p, inst end %p\n", target_branch,
        //        inst_end);
        ASSERT(op->size_orig == 5);
        new_op = dasm::maker();
        xed_inst1(&new_op.enc_inst, new_op.dstate,
                XED_ICLASS_JMP, 32,
                xed_relbr((uint32_t)(target_branch - inst_end),  32)
                );
        new_size = new_op.make(buf + inst_size, buf_size - inst_size);
        ASSERT(new_size == 5);
        inst_size += new_size;
    } 
    else if (target_op_name == XED_OPERAND_MEM0) {
        //SAY_DEBUG("XED_OPERAND_MEM0, reg = %s, disp = %x(%d)\n",
        //        xed_reg_enum_t2str(op->reg_base),
        //        op->mem_disp, op->mem_disp_width);

        if (op->reg_base == XED_REG_RIP) {
            uint32_t jmp_size = 6;
            new_op = dasm::maker();
            ASSERT(op->mem_disp_width * 8 == 32);

            size_t target_disp = target_addr + op->mem_disp;
            size_t inst_end = m_inst_code->addr_remote() + m_inst_offset + 
                inst_size + jmp_size;
            //SAY_DEBUG("target + disp %p, inst end %p\n", target_disp,
            //        inst_end);

            xed_inst1(&new_op.enc_inst, new_op.dstate,
                    XED_ICLASS_JMP, sizeof(size_t) * 8,
                    xed_mem_bisd(op->reg_base, 
                        op->reg_index, 
                        op->scale,
                        xed_disp(target_disp - inst_end, 
                            op->mem_disp_width * 8), 
                        sizeof(size_t) * 8)
                    );
            new_size = new_op.make(buf + inst_size, buf_size - inst_size);
            ASSERT(new_size == jmp_size);
            inst_size += new_size;
#ifndef _WIN64
            SAY_FATAL("translating call to jump [rel mem] %p\n", buf);
#endif
        }
        else {
            // call qword ptr [rax]
            uint32_t jmp_size = op->size_orig;
            new_op = dasm::maker();
            //SAY_DEBUG("mem disp = %x, buf: %p\n", op->mem_disp_width, buf);

            xed_inst1(&new_op.enc_inst, new_op.dstate,
                    XED_ICLASS_JMP, sizeof(size_t) * 8,
                    xed_mem_bisd(op->reg_base, 
                        op->reg_index, 
                        op->scale,
                        xed_disp(op->mem_disp, 
                            op->mem_disp_width * 8), 
                        sizeof(size_t) * 8)
                    );
            new_size = new_op.make(buf + inst_size, buf_size - inst_size);
            ASSERT(new_size == jmp_size);
            inst_size += new_size;
        }
    }
    else if (target_op_name == XED_OPERAND_REG0) {
        // call rax
        uint32_t jmp_size = op->size_orig;
        new_op = dasm::maker();

        xed_inst1(&new_op.enc_inst, new_op.dstate,
                XED_ICLASS_JMP, sizeof(size_t)*8,
                xed_reg(op->reg0)
                );
        new_size = new_op.make(buf + inst_size, buf_size - inst_size);
        ASSERT(new_size == jmp_size);
        inst_size += new_size;
    }
    else {
        SAY_FATAL("Invalid call type, use --disasm to see which one\n");
    }

    return inst_size;
}

uint32_t translator::make_1byte_jump_from_orig_to_orig(
        size_t jump_from, size_t jump_to)
{
    ASSERT((int)(jump_to - (jump_from + 2)) / 0x80 == 0);

    size_t text_offset = jump_from - m_text_sect->addr_remote();
    uint32_t inst_size = 2;

    size_t bits = 8;
    size_t disp = jump_to - (jump_from + inst_size);
    auto op = dasm::maker();
    xed_inst1(&op.enc_inst, op.dstate,
            XED_ICLASS_JMP, 8,
            xed_relbr((uint32_t)disp, 8));
    auto new_inst_size = op.make(
            (uint8_t*)(m_text_sect->addr_loc_raw() + text_offset), 
            inst_size);
    ASSERT(new_inst_size == inst_size);
    return new_inst_size;
}

uint32_t translator::make_jump_from_orig_to_inst(
        size_t jump_from, size_t jump_to)
{
    size_t text_offset = jump_from - m_text_sect->addr_remote();

    uint32_t inst_size = 5;

    size_t bits = 32;
    size_t disp = jump_to - (jump_from + inst_size);
    auto op = dasm::maker();
    xed_inst1(&op.enc_inst, op.dstate,
            XED_ICLASS_JMP, 32,
            xed_relbr((uint32_t)disp, 32));
    auto new_inst_size = op.make(
            (uint8_t*)(m_text_sect->addr_loc_raw() + text_offset), 
            inst_size);
    ASSERT(new_inst_size == inst_size);
    return new_inst_size;
}

// This functions suggests overwring of code (not sequential write like others
// make_jump_* ones
uint32_t translator::make_jump_from_inst_to_inst(
        size_t jump_from, size_t jump_to) 
{

    uint32_t inst_size = 5;
    ASSERT(jump_to - jump_from >= inst_size);

    size_t bits = 32;
    size_t disp = jump_to - (jump_from + inst_size);

    size_t inst_offset = jump_from - m_inst_code->addr_remote();

    auto op = dasm::maker();
    xed_inst1(&op.enc_inst, op.dstate,
            XED_ICLASS_JMP, 32,
            xed_relbr((uint32_t)disp, 32));
    auto new_inst_size = op.make(
            (uint8_t*)(m_inst_code->addr_loc_raw() + inst_offset), 
            inst_size);

    ASSERT(new_inst_size == inst_size);
    return new_inst_size;
}


// Here we do quite simple instrumentation. We instrument only one basic block
// from the perspective of current pointer, meaning if then discovered jump to
// the middle of existing basic block, we will create new one with partial code
// duplication. We also do not follow any references in advance. 
// This strategy leads to the instrumentation of only code wich is hit.
// UPD: if we have bb info from IDA we can instrument all the bbs of the 
// binary and it will be much faster overall

size_t translator::translate(size_t addr, 
        uint32_t* instrumented_size,
        uint32_t* original_size)
{

    static auto one_time_init = false;
    if (!one_time_init) {
        xed_tables_init();
        one_time_init = true;
    }

    m_stats.translated_bbs++;
    auto rip = addr;
    size_t bb_start = 0;
    size_t inst_start_offset = m_inst_offset;
    size_t inst_count = 0;
    uint32_t orig_size = 0;
    while(1) {
        // should instrument instruction
        if (!bb_start) {
            auto remote_inst = m_inst_code->addr_remote() + m_inst_offset;
            bb_start = remote_inst;
            m_remote_orig_to_inst_bb[rip] = remote_inst;
            if (m_opts.debug)
                SAY_DEBUG("Remote bb got instrumented %p -> %p\n", 
                        rip, remote_inst);
            make_dword_inc_cov_hit();
            //make_dword_mov_cov_hit();
            remote_inst = m_inst_code->addr_remote() + m_inst_offset;
        }

        // disasm & cache
        auto offset = rip - m_text_sect_remote_addr;
        auto local_addr = m_opts.shadow_code ? 
            m_opts.shadow_code->addr_loc_raw() + offset:
            m_text_sect->addr_loc_raw() + offset;
        if (m_opts.debug)
            SAY_DEBUG("Disasm (%x) local: %p remote: %p text sect remote: "
                    "%p\n", 
                    offset, local_addr, rip, m_text_sect_remote_addr);

        //auto op = m_dasm_cache.get(local_addr, rip);
        auto o = dasm::opcode::opcode(local_addr, rip);
        auto op = &o;

        if (m_opts.disasm || m_opts.debug)
        {
            char buf[128];
            auto r = xed_format_context(XED_SYNTAX_INTEL, 
                    &op->xedd,
                    buf,
                    sizeof(buf), 0, 0, 0);
            SAY_INFO("%p %p %-30s (Category: %s, iclass: %s)\n",
                    rip, 
                    m_inst_code->addr_remote() + m_inst_offset,
                    buf,
                    xed_category_enum_t2str(op->category),
                    xed_iclass_enum_t2str(op->iclass));
        }

        orig_size += op->size_orig;
        if (m_opts.cmpcov && 
                !is_target_le_8bits(op)) // skip single bytes comparisons
        {
            bool should_add_cmp_inst = false;

            // TODO:
            if (//op->iclass == XED_ICLASS_ADD ||
                    // op->iclass == XED_ICLASS_XOR ||
                    op->iclass == XED_ICLASS_SUB
                    ) {
                auto op_next = m_dasm_cache.get(local_addr + op->size_orig,
                        rip + op->size_orig);
                if (op_next->is_cond_jump()) {
                    m_stats.cmpcov_sub++;
                    should_add_cmp_inst = true;
                }
            }
            if (op->iclass == XED_ICLASS_CMP) {
                m_stats.cmpcov_cmp++;
                should_add_cmp_inst = true;
            }

            if (op->iclass == XED_ICLASS_TEST) {
                m_stats.cmpcov_test++;
                should_add_cmp_inst = true;
            }

            if (should_add_cmp_inst) {
                add_cmpcov_inst(rip, op);
            }
        }

        //if (rip == 0x07FFBEE6B17F0
        //        ) {
        //    SAY_INFO("*** setting break***\n");
        //    *(char*)get_inst_ptr() = 0xcc;
        //    adjust_inst_offset(1);
        //}

        uint32_t inst_sz = 0;
        if (m_opts.call_to_jmp &&
            op->category == XED_CATEGORY_CALL) {
            inst_sz = translate_call_to_jump(op, get_inst_ptr(),
                    get_inst_bytes_left(), rip + op->size_orig);
        }
        else {
            inst_sz = op->rebuild_to_new_addr(get_inst_ptr(),
                    get_inst_bytes_left(), 
                    m_inst_code->addr_remote() + m_inst_offset);
        }
        ASSERT(inst_sz);

        adjust_inst_offset(inst_sz);
        inst_count += 1;

        if (op->branch_disp_width) {
            m_remote_dd_refs.insert(
                    m_inst_code->addr_remote() + m_inst_offset - 4);
        }

        if (op->category == XED_CATEGORY_CALL && m_opts.call_to_jmp) {
            break;
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
        auto should_stop = false;

        if (op->is_iclass_jxx()) should_stop = true;
        if (m_opts.single_step) should_stop = true;
        if (m_bbs &&
                (m_bbs->find(rip + op->size_orig) != m_bbs->end()))
            should_stop = true;

        if (should_stop) {
            // place new jump to keep code linked
            auto tgt_addr = op->size_orig + op->addr;
            make_jump_to_orig_or_inst(tgt_addr);
            m_remote_dd_refs.insert(
                    m_inst_code->addr_remote() + m_inst_offset - 4);
            break;
        }

        // continue the loop
        rip += op->size_orig;
    }

    auto inst_size = m_inst_offset - inst_start_offset;
    if (instrumented_size) *instrumented_size = (uint32_t)inst_size;
    if (original_size) {
        if (orig_size < 5) {
            for (size_t i = 0; i < 4; i++) {
                // if we have 0xcc after a basicblock end, we can safely use it
                auto offset = orig_size + addr - m_text_sect_remote_addr;
                auto base = 
                    m_opts.shadow_code ? 
                    m_opts.shadow_code->addr_loc_raw() : 
                    m_text_sect->addr_loc_raw();
                if (0xcc == *(uint8_t*)(base + offset + i)) {
                    orig_size++;
                }
                else {
                    break;
                }
            }
        }
        *original_size = orig_size;
    }

    return m_remote_orig_to_inst_bb[addr];
}

translator::translator(mem_tool* inst_code, 
        mem_tool* cov_buf, 
        mem_tool* cmpcov_buf,
        mem_tool* text_sect,
        size_t text_sect_remote_addr):
    m_inst_code(inst_code),
    m_cov_buf(cov_buf),
    m_cmpcov_buf(cmpcov_buf),
    m_text_sect(text_sect),
    m_text_sect_remote_addr(text_sect_remote_addr)
{
    ASSERT(m_inst_code);
    ASSERT(m_cov_buf);
    ASSERT(m_cmpcov_buf);
    ASSERT(m_text_sect);
}

size_t translator::remote_orig_to_inst_bb(size_t addr) {
    return m_remote_orig_to_inst_bb.find(addr) == 
        m_remote_orig_to_inst_bb.end() ?
        0 : 
        m_remote_orig_to_inst_bb[addr];
}
