
/*
 * Simple assembler/disassembler helper based on xed
 */

#ifndef DASM_H
#define DASM_H

extern "C" {
#include "xed/xed-interface.h"
}

#include <stdint.h>
#include <map>
#include <vector>

#define DASM_MAX_OPCODE_LEN 0x20

namespace dasm {

    struct maker {

        xed_error_enum_t          err;
        xed_encoder_request_t     req;
        xed_encoder_instruction_t enc_inst;
        xed_state_t               dstate;

        maker();
        uint32_t make(uint8_t* output_data, uint32_t output_size);
    };

    struct opcode {

        xed_iclass_enum_t   iclass = XED_ICLASS_INVALID;
        size_t              mem_disp = 0;
        uint32_t            mem_disp_width = 0;
        uint8_t             mem_ops_num = 0;
        uint32_t            mem_len0 = 0;
        uint32_t            mem_len1 = 0;
        uint32_t            imm = 0;
        uint32_t            imm_width = 0;
        uint32_t            op_width = 0;
        size_t              branch_disp = 0;
        uint32_t            branch_disp_width = 0;
        uint32_t            size_new = 0;
        uint32_t            size_orig = 0;
        size_t              addr = 0;
        uint32_t            scale = 0;
        uint8_t             opcode_data[DASM_MAX_OPCODE_LEN];

        xed_reg_enum_t      reg_base = XED_REG_INVALID;
        xed_reg_enum_t      reg_index = XED_REG_INVALID;
        xed_reg_enum_t      reg0 = XED_REG_INVALID;
        xed_reg_enum_t      reg1 = XED_REG_INVALID;
        xed_reg_enum_t      reg0_largest = XED_REG_INVALID;
        xed_reg_enum_t      reg0_smallest = XED_REG_INVALID;
        xed_reg_enum_t      reg1_largest = XED_REG_INVALID;
        xed_reg_enum_t      reg1_smallest = XED_REG_INVALID;
        xed_reg_enum_t      seg_reg = XED_REG_INVALID;
        xed_category_enum_t category = XED_CATEGORY_INVALID;
        xed_operand_enum_t  first_op_name = XED_OPERAND_INVALID;
        xed_operand_enum_t  second_op_name = XED_OPERAND_INVALID;

        xed_decoded_inst_t  xedd;
        const xed_inst_t*        xi = NULL;
        const xed_operand_t*     first_op = NULL;
        const xed_operand_t*     second_op = NULL;

        /*
         * Simplest ctor provide only data and VA
         */
        opcode(){};
        opcode(size_t data, size_t addr = 0);

        uint8_t* rebuild();
        uint32_t rebuild_to_new_addr(
                uint8_t* buf, uint32_t buf_size, size_t new_addr);
        xed_decoded_inst_t* get_xedd_ptr() {
            return &xedd;
        };
        bool fix_branch_disp(size_t new_addr);
        bool fix_mem_disp(size_t new_addr);
        bool is_iclass_jxx();
        bool is_cond_jump();
        static xed_reg_enum_t get_reg_from_largest(
                xed_reg_enum_t reg, uint32_t width);

    };

    class cached_code {
        /* 
         * This maintains the series of opcodes cached in memory, thus you 
         * don't need to disassemble it each time, but the trade off is memory
         * usage
         */

        public:

            /*
             * Gets opcode and caches it
             *
             * NOTE: previous pointer can become invalid if you call this
             * function several times
             */
            opcode* get(size_t ptr);
            opcode* get(size_t data, size_t addr);

            /*
             * Cleans all the resources
             */
            void clean() {
                m_opcodes.clear();
            }; 

            void invalidate(size_t ptr) {
                m_opcodes.erase(ptr);
            }

        private:

            std::map<size_t, opcode>      m_opcodes;


    };

};

#endif // DASM_H
