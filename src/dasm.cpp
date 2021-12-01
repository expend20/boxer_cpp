#include "dasm.h"
#include "say.h"

#define OPCODE_MAX_LEN 0x20

bool g_debug = true;

xed_reg_enum_t _regs8[] = {XED_REG_AL, XED_REG_BL, XED_REG_CL, XED_REG_DL,
    XED_REG_SIL, XED_REG_DIL, XED_REG_BPL, XED_REG_SPL, XED_REG_R8B, XED_REG_R9B,
    XED_REG_R10B, XED_REG_R11B, XED_REG_R12B, XED_REG_R13B, XED_REG_R14B,
    XED_REG_R15B};
xed_reg_enum_t _regs16[] = {XED_REG_AX, XED_REG_BX, XED_REG_CX, XED_REG_DX,
    XED_REG_SI, XED_REG_DI, XED_REG_BP, XED_REG_SP, XED_REG_R8W, XED_REG_R9W,
    XED_REG_R10W, XED_REG_R11W, XED_REG_R12W, XED_REG_R13W, XED_REG_R14W,
    XED_REG_R15W};
xed_reg_enum_t _regs32[] = {XED_REG_EAX, XED_REG_EBX, XED_REG_ECX, XED_REG_EDX,
    XED_REG_ESI, XED_REG_EDI, XED_REG_EBP, XED_REG_ESP, XED_REG_R8D, XED_REG_R9D,
    XED_REG_R10D, XED_REG_R11D, XED_REG_R12D, XED_REG_R13D, XED_REG_R14D,
    XED_REG_R15D};
xed_reg_enum_t _regs64[] = {XED_REG_RAX, XED_REG_RBX, XED_REG_RCX, XED_REG_RDX,
    XED_REG_RSI, XED_REG_RDI, XED_REG_RBP, XED_REG_RSP, XED_REG_R8, XED_REG_R9,
    XED_REG_R10, XED_REG_R11, XED_REG_R12, XED_REG_R13, XED_REG_R14,
    XED_REG_R15};

xed_reg_enum_t dasm::opcode::get_reg_from_largest(
        xed_reg_enum_t reg, uint32_t width){
    xed_reg_enum_t* target;
    switch(width) {
        case 8:
            target = _regs8;
            break;
        case 16:
            target = _regs16;
            break;
        case 32:
            target = _regs32;
            break;
        case 64:
            target = _regs64;
            break;
        default:
            SAY_FATAL("Unknown width: %d", width);
            break;
    }
    for (uint32_t i = 0; i < sizeof(_regs8); i++) {
        if (_regs64[i] == reg) return target[i];
    }
    return reg;
}

xed_reg_enum_t dasm::opcode::get_reg_except_this_list(
        xed_reg_enum_t* reg_buf, // should be largest ones
        uint32_t reg_buf_count){
    xed_reg_enum_t allowed_reg_w8[] = {
        XED_REG_RAX, XED_REG_RBX, XED_REG_RCX, XED_REG_RDX,
        XED_REG_RSI, XED_REG_RDI, /*XED_REG_RBP, XED_REG_RSP,*/ 
        XED_REG_R8, XED_REG_R9, XED_REG_R10, XED_REG_R11, XED_REG_R12,
        XED_REG_R13, XED_REG_R14, XED_REG_R15};

    ASSERT(reg_buf);
    ASSERT(reg_buf_count);

    for (size_t i = 0; i < sizeof(allowed_reg_w8); i++) {
        bool is_found = false;
        for (size_t j = 0; j < reg_buf_count; j++) {
            if (allowed_reg_w8[i] == reg_buf[j]) {
                is_found = true;
                break;
            }
        }
        if (!is_found) return allowed_reg_w8[i];
    }

    SAY_FATAL("can't find proper register");
    return (xed_reg_enum_t)-1;
}

bool dasm::opcode::is_cond_jump() 
{
    if (is_iclass_jxx() && iclass != XED_ICLASS_JMP) {
        return true;
    }
    else {
        return false;
    }
}

bool dasm::opcode::is_iclass_jxx()
{
    auto res = false;
    switch (iclass) {
        case XED_ICLASS_JMP:

        case XED_ICLASS_JB:
        case XED_ICLASS_JBE:
        case XED_ICLASS_JCXZ:
        case XED_ICLASS_JECXZ:
        case XED_ICLASS_JL:
        case XED_ICLASS_JLE:
        case XED_ICLASS_JNB:
        case XED_ICLASS_JNBE:
        case XED_ICLASS_JNL:
        case XED_ICLASS_JNLE:
        case XED_ICLASS_JNO:
        case XED_ICLASS_JNP:
        case XED_ICLASS_JNS:
        case XED_ICLASS_JNZ:
        case XED_ICLASS_JO:
        case XED_ICLASS_JP:
        case XED_ICLASS_JRCXZ:
        case XED_ICLASS_JS:
        case XED_ICLASS_JZ:
            res = true;
            break;
        default:
            break;
    }
    return res;
}

uint32_t dasm::opcode::rebuild_to_new_addr(
        uint8_t* buf, uint32_t buf_size, size_t new_addr)
{
    xed_encoder_request_init_from_decode(&xedd);
    bool should_rebuild = false;
    should_rebuild = fix_mem_disp(new_addr) ||
        fix_branch_disp(new_addr);

    xed_error_enum_t xed_error;

    if (!should_rebuild) {
        // just copy the instructions, this sould be faster
        //xed_error = xed_encode(
        //        &xedd, (unsigned char*)buf, buf_size, &size_new);
        memcpy(buf, (void*)opcode_data, size_orig);
        size_new = size_orig;
    } else {

        xed_error = xed_encode(&xedd, (unsigned char*)buf, buf_size, &size_new);
        if (xed_error != XED_ERROR_NONE) {
            SAY_FATAL("Error encoding instruction");
        }
        // instruction size might be changed 
        if (size_orig != size_new) {
            // ...thus made invalid code, because it was calculated using
            // previous size
            fix_mem_disp(new_addr);
            fix_branch_disp(new_addr);

            xed_error = xed_encode(
                    &xedd, (unsigned char*)buf, buf_size, &size_new);
            if (xed_error != XED_ERROR_NONE) {
                SAY_FATAL("Error encoding instruction");
            }
        }
    }
    return size_new ? size_new : size_orig;
}

bool dasm::opcode::fix_branch_disp(size_t new_addr){
    if (branch_disp_width) {
        auto tgt_addr = addr + branch_disp + size_orig;
        auto branch_disp_new = tgt_addr - 
            (new_addr + (size_new ? size_new : size_orig));
        if (g_debug)
            SAY_DEBUG("tgt_addr %p, new_addr %p, size_orig %x, "\
                    "size_new %x, orig_disp %p, new_disp %x\n", 
                    tgt_addr, new_addr, size_orig, size_new, 
                    branch_disp, 
                    branch_disp_new);
        xed_encoder_request_set_branch_displacement(&xedd, 
                (uint32_t)branch_disp_new, 4);
        return true;
    }
    return false;
}

bool dasm::opcode::fix_mem_disp(size_t new_addr){
    if (mem_disp_width && reg_base == XED_REG_RIP) {
        auto tgt_addr = addr + mem_disp + size_orig;
        auto new_addr_end = new_addr + (size_new ? size_new : size_orig);
        auto new_mem_disp = tgt_addr -  new_addr_end;
        if (g_debug)
            SAY_DEBUG("tgt_addr %p, new_addr %p, new_addr_end %p, "
                    "size_orig %x, size_new %x, orig_disp %p, new_disp %x\n", 
                    tgt_addr, new_addr, new_addr_end, size_orig, size_new, 
                    mem_disp, new_mem_disp);
        xed_encoder_request_set_memory_displacement(
                &xedd, new_mem_disp, mem_disp_width);
        ASSERT(mem_disp_width == 4);
        return true;
    }
    return false;
}

dasm::maker::maker() 
{

    xed_state_zero(&dstate);
#ifdef _WIN64
    dstate.mmode = XED_MACHINE_MODE_LONG_64;
    dstate.stack_addr_width = XED_ADDRESS_WIDTH_64b;
#else 
    dstate.mmode = XED_MACHINE_MODE_LEGACY_32;
    dstate.stack_addr_width = XED_ADDRESS_WIDTH_32b;
#endif

}

uint32_t dasm::maker::make(uint8_t* output_data, uint32_t output_size)
{
    xed_encoder_request_zero_set_mode(&req, &dstate);
    auto r = xed_convert_to_encoder_request(&req, &enc_inst);
    if (!r) {
        SAY_FATAL("Can't convert to encoder request");
    }

    uint32_t new_len = 0;
    err = xed_encode(&req, (uint8_t*)output_data, output_size, &new_len);
    if (err != XED_ERROR_NONE) {
        SAY_FATAL("Error encoding instruction %s",
                xed_error_enum_t2str(err));
    }
    return new_len;
}

dasm::opcode::opcode(size_t data, size_t addr_arg) {

    ASSERT(data);
    if (!addr_arg) { addr_arg = data; }
    addr = addr_arg;

    xed_error_enum_t         xed_error;
    xed_machine_mode_enum_t  mmode;
    xed_address_width_enum_t stack_addr_width;

#ifdef _WIN64
    mmode = XED_MACHINE_MODE_LONG_64;
    stack_addr_width = XED_ADDRESS_WIDTH_64b;
#else 
    mmode = XED_MACHINE_MODE_LEGACY_32;
    stack_addr_width = XED_ADDRESS_WIDTH_32b;
#endif

    xed_decoded_inst_zero(&xedd);
    xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);

    xed_error = xed_decode(&xedd, (xed_uint8_t*)data, OPCODE_MAX_LEN);
    if (xed_error != XED_ERROR_NONE) {
        SAY_ERROR("Error decoding %d (%s), ptr %p %p\n", 
                xed_error, 
                xed_error_enum_t2str(xed_error),
                data, 
                addr);
        __debugbreak();
        return;
    }

    size_orig   = xed_decoded_inst_get_length(&xedd);
    ASSERT(sizeof(opcode_data) >= size_orig);
    memcpy(opcode_data, (void*)data, size_orig);
    iclass      = xed_decoded_inst_get_iclass(&xedd);
    reg_base    = xed_decoded_inst_get_base_reg(&xedd, 0);
    mem_ops_num = xed_decoded_inst_number_of_memory_operands(&xedd);

    // jmp rel32
    branch_disp  = xed_decoded_inst_get_branch_displacement(&xedd);
    branch_disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);

    // jmp [rel32]
    mem_disp  = (size_t)xed_decoded_inst_get_memory_displacement(&xedd, 0);
    mem_disp_width = xed_decoded_inst_get_memory_displacement_width(&xedd, 0);

    category       = xed_decoded_inst_get_category(&xedd);
    xi             = xed_decoded_inst_inst(&xedd);
    first_op       = xed_inst_operand(xi, 0);
    first_op_name  = xed_operand_name(first_op);
    second_op      = xed_inst_operand(xi, 1);
    second_op_name = xed_operand_name(second_op);
    reg_index      = xed_decoded_inst_get_index_reg(&xedd, 0);
    scale          = xed_decoded_inst_get_scale(&xedd, 0);
    seg_reg        = xed_decoded_inst_get_seg_reg(&xedd, 0);
    mem_len0       = xed_decoded_inst_get_memory_operand_length(&xedd, 0) * 8;
    mem_len1       = xed_decoded_inst_get_memory_operand_length(&xedd, 1) * 8;
    reg0           = xed_decoded_inst_get_reg(&xedd, XED_OPERAND_REG0);
    if (reg0 != XED_REG_INVALID) {
        reg0_largest = xed_get_largest_enclosing_register(reg0);
        reg0_smallest = get_reg_from_largest(reg0_largest, 8);
    }
    reg1           = xed_decoded_inst_get_reg(&xedd, XED_OPERAND_REG1);
    if (reg1 != XED_REG_INVALID) {
        reg1_largest = xed_get_largest_enclosing_register(reg1);
        reg1_smallest = get_reg_from_largest(reg1_largest, 8);
    }
    op_width       = xed_decoded_inst_get_operand_width(&xedd);
    imm_width      = xed_decoded_inst_get_immediate_width_bits(&xedd);
    imm            = xed_decoded_inst_get_unsigned_immediate(&xedd);

    /*
       uint32_t opWidthBits = xed_decoded_inst_get_operand_width(xedd);
       uint32_t memWidth = memWidth0 >= memWidth1 ? memWidth0 : memWidth1;
       xed_uint_t immWidth = xed_decoded_inst_get_immediate_width(xedd);
       xed_reg_enum_t reg0Largest = xed_get_largest_enclosing_register(reg0);
       xed_reg_enum_t reg0Lowest = GetRegFromLargest(reg0Largest, 1);
       xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
       xed_reg_enum_t reg1Largest = xed_get_largest_enclosing_register(reg1);
       xed_reg_enum_t reg1Lowest = GetRegFromLargest(reg1Largest, 1);
       */
}

dasm::opcode* dasm::cached_code::get(size_t data, size_t addr) {

    auto el = m_opcodes.find(addr);
    if (el == m_opcodes.end()) {
        m_opcodes[addr] = opcode(data, addr);
    }
    return &m_opcodes[addr];
}

dasm::opcode* dasm::cached_code::get(size_t addr) {

    auto el = m_opcodes.find(addr);
    if (el == m_opcodes.end()) {
        m_opcodes[addr] = opcode(addr);
    }
    return &m_opcodes[addr];
}

