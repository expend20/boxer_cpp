
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

        xed_iclass_enum_t   iclass;
        size_t              mem_disp;
        size_t              mem_disp_addr;
        uint32_t            mem_disp_width;
        uint8_t             mem_ops_num;
        uint32_t            mem_len;
        size_t              branch_disp;
        size_t              branch_disp_addr;
        uint32_t            branch_disp_width;
        size_t              size;
        xed_reg_enum_t      reg_base;
        xed_reg_enum_t      reg_index;
        xed_reg_enum_t      reg0;
        xed_reg_enum_t      seg_reg;
        uint32_t            scale;
        xed_decoded_inst_t  xedd;
        size_t              addr;
        uint8_t             opcode_data[DASM_MAX_OPCODE_LEN];
        xed_category_enum_t category;

        const xed_inst_t*        xi;
        const xed_operand_t*     first_op;

        xed_operand_enum_t first_op_name;
        /*
         * Simplest ctor provide only data and VA
         */
        opcode(){};
        opcode(size_t data, size_t addr = 0);

        uint8_t* rebuild();
        size_t rebuild_to_new_addr(
                uint8_t* buf, size_t buf_size, size_t new_addr);
        xed_decoded_inst_t* get_xedd_ptr() {
            return &xedd;
        };
        bool fix_rip_rel(size_t new_addr);
        bool make_jxx_32bits(size_t new_addr);
        bool is_iclass_jxx();

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
                m_idxes.clear();
                m_opcodes.clear();
            }; 

            void invalidate(size_t ptr) {
                m_idxes.erase(ptr);
            }

        private:

            std::map<size_t, size_t> m_idxes;
            std::vector<opcode>      m_opcodes;


    };

};

#endif // DASM_H
