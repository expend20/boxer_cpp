#include "dasm.h"
#include "say.h"

#define OPCODE_MAX_LEN 0x20

bool dasm::opcode::is_iclass_jxx() {
    auto res = false;
    switch (iclass) {
        case XED_ICLASS_JB:
        case XED_ICLASS_JBE:
        case XED_ICLASS_JCXZ:
        case XED_ICLASS_JECXZ:
        case XED_ICLASS_JL:
        case XED_ICLASS_JLE:
        case XED_ICLASS_JMP:
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

size_t dasm::opcode::rebuild_to_new_addr(
        uint8_t* buf, size_t buf_size, size_t new_addr)
{
    xed_encoder_request_init_from_decode(&xedd);
    bool should_rebuild = false;
    should_rebuild = fix_mem_disp(new_addr) ||
        fix_branch_disp(new_addr);

    xed_error_enum_t xed_error;

    if (!should_rebuild) {
        // just copy the instructions
        // TODO: replace to memcpy, beware, if we rebuild, size might change
        xed_error = xed_encode(
                &xedd, (unsigned char*)buf, buf_size, &size_new);
        //ASSERT(size_orig == size_new);
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
        SAY_DEBUG("tgt_addr %p, new_addr %p, size_orig %x, "\
                "size_new %x, orig_disp %p, new_disp %x\n", 
                tgt_addr, new_addr, size_orig, size_new, 
                branch_disp, 
                branch_disp_new);
        xed_encoder_request_set_branch_displacement(&xedd, branch_disp_new, 4);
        return true;
    }
    return false;
}

bool dasm::opcode::fix_mem_disp(size_t new_addr){
    if (mem_disp_width && reg_base == XED_REG_RIP) {
        auto tgt_addr = addr + mem_disp + size_orig;
        auto new_addr_end = new_addr + (size_new ? size_new : size_orig);
        auto new_mem_disp = tgt_addr -  new_addr_end;
        SAY_DEBUG("tgt_addr %p, new_addr %p, new_addr_end %p, size_orig %x, "\
                "size_new %x, orig_disp %p, new_disp %x\n", 
                tgt_addr, new_addr, new_addr_end, size_orig, size_new, mem_disp, 
                new_mem_disp);
        xed_encoder_request_set_memory_displacement(
                &xedd, new_mem_disp, mem_disp_width);
        ASSERT(mem_disp_width == 4);
        return true;
    }
    return false;
}

//bool dasm::opcode::make_jxx_32bits(size_t new_addr){
//    if (branch_disp_width) {
//        //SAY_INFO("Branch disp width %x %x %x\n",
//        //        branch_disp,
//        //        branch_disp_width,
//        //        branch_disp_addr);
//
//        if (branch_disp_width != 4) {
//            uint8_t buf[0x20];
//            //SAY_INFO("Branch disp width changed to 4\n");
//
//            // prebuild opcode to get new size
//            xed_encoder_request_set_branch_displacement(
//                    &xedd, branch_disp, 4);
//            auto r = xed_encode(&xedd, buf, sizeof(buf), &size_new);
//            ASSERT(r == XED_ERROR_NONE);
//
//        }
//        return true;
//    }
//    return false;
//}

//bool dasm::opcode::fix_rip_rel(size_t new_addr){
//    if (mem_disp_width && reg_base == XED_REG_RIP) {
//        //SAY_INFO("addr/memdisp/size %p/%p/%p\n", addr, mem_disp, size);
//        auto tgt_addr = addr + mem_disp + size_orig;
//        auto new_addr_end = new_addr + (size_new ? size_new : size_orig);
//        int32_t new_mem_disp = tgt_addr -  new_addr_end;
//        SAY_INFO("tgt_addr %p, new_addr %p, new_addr_end %p, size_orig %x, "\
//                "size_new %x, orig_disp %p, new_disp %p\n", 
//                tgt_addr, new_addr, new_addr_end, size_orig, size_new, mem_disp, 
//                new_mem_disp);
//
//        ASSERT(mem_disp_width == 4);
//
//        // let's check if new opcode has the same size
//        auto r = xed_encode(&xedd, buf, sizeof(buf), &size_new);
//        ASSERT(r == XED_ERROR_NONE);
//        if (size_new != size_orig) {
//        }
//
//        xed_encoder_request_set_memory_displacement(
//                &xedd, new_mem_disp, mem_disp_width);
//
//        return true;
//    }
//    return false;
//}

dasm::maker::maker() 
{
    dstate.mmode = XED_MACHINE_MODE_LONG_64;
    dstate.stack_addr_width = XED_ADDRESS_WIDTH_64b;
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

    mmode            = XED_MACHINE_MODE_LONG_64;
    stack_addr_width = XED_ADDRESS_WIDTH_64b;

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
    iclass      = xed_decoded_inst_get_iclass(&xedd);
    reg_base    = xed_decoded_inst_get_base_reg(&xedd, 0);
    mem_ops_num = xed_decoded_inst_number_of_memory_operands(&xedd);

    // jmp rel32
    branch_disp  = xed_decoded_inst_get_branch_displacement(&xedd);
    branch_disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);

    // jmp [rel32]
    mem_disp  = xed_decoded_inst_get_memory_displacement(&xedd, 0);
    mem_disp_width = xed_decoded_inst_get_memory_displacement_width(&xedd, 0);

    category      = xed_decoded_inst_get_category(&xedd);
    xi            = xed_decoded_inst_inst(&xedd);
    first_op      = xed_inst_operand(xi, 0);
    first_op_name = xed_operand_name(first_op);
    reg_index     = xed_decoded_inst_get_index_reg(&xedd, 0);
    scale         = xed_decoded_inst_get_scale(&xedd, 0);
    seg_reg       = xed_decoded_inst_get_seg_reg(&xedd, 0);
    mem_len       = xed_decoded_inst_get_memory_operand_length(&xedd, 0);
    reg0          = xed_decoded_inst_get_reg(&xedd, XED_OPERAND_REG0);

    /*
       const xed_inst_t* xi = xed_decoded_inst_inst(xedd);
       xed_uint_t noperands = xed_inst_noperands(xi);
       const xed_operand_t* firstOperand, * secondOperand;
       firstOperand = xed_inst_operand(xi, 0);
       secondOperand = xed_inst_operand(xi, 1);
       xed_operand_enum_t firstName, secondName;
       firstName = xed_operand_name(firstOperand);
       secondName = xed_operand_name(secondOperand);
       uint32_t memWidth0 = xed_decoded_inst_get_memory_operand_length(xedd, 0);
       uint32_t memWidth1 = xed_decoded_inst_get_memory_operand_length(xedd, 1);
       uint32_t opWidthBits = xed_decoded_inst_get_operand_width(xedd);
       uint32_t memWidth = memWidth0 >= memWidth1 ? memWidth0 : memWidth1;
       xed_uint_t immWidth = xed_decoded_inst_get_immediate_width(xedd);
       xed_reg_enum_t reg0Largest = xed_get_largest_enclosing_register(reg0);
       xed_reg_enum_t reg0Lowest = GetRegFromLargest(reg0Largest, 1);
       xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
       xed_reg_enum_t reg1Largest = xed_get_largest_enclosing_register(reg1);
       xed_reg_enum_t reg1Lowest = GetRegFromLargest(reg1Largest, 1);
       uint64_t imm = xed_decoded_inst_get_unsigned_immediate(xedd);
       */
}

dasm::opcode* dasm::cached_code::get(size_t data, size_t addr) {

    auto r = m_idxes.find(addr);
    if (r == m_idxes.end()) {

        /*
         * Add new opcode
         */

        auto op = opcode(data, addr);
        auto idx = m_opcodes.size();
        m_opcodes.push_back(op);
        m_idxes[addr] = idx;

        return &m_opcodes[idx];

    } else {

        return &m_opcodes[r->second];

    }
}
dasm::opcode* dasm::cached_code::get(size_t ptr) {

    auto r = m_idxes.find(ptr);
    if (r == m_idxes.end()) {

        /*
         * Add new opcode
         */

        auto op = opcode(ptr);
        auto idx = m_opcodes.size();
        m_opcodes.push_back(op);
        m_idxes[ptr] = idx;

        return &m_opcodes[idx];

    } else {

        return &m_opcodes[r->second];

    }
}

