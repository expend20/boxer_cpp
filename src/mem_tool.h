/*
 * This module provides transparent primitive to work with memory in
 * different processes, so you can work either with memory of this proceses
 * or any other processes
 */

#ifndef __MEMORY_TOOL_H
#define __MEMORY_TOOL_H

#include <stdint.h>
#include <vector>
#include <windows.h>

class mem_tool {

    public:
        mem_tool(){};
        mem_tool(HANDLE process, size_t data, size_t len);

        // Use this 
        size_t begin_addr_loc();
        void begin();
        void end();

        size_t get_mem_by_offset(size_t offset);
        size_t get_mem_by_addr(size_t addr);

        size_t get_tgt_by_offset(size_t offset);
        size_t get_tgt_by_local(size_t localAddress);

        bool   is_in_rage_remote(size_t addr);

        size_t get_bytes_left_by_addr(size_t addr);


        void commit_remote();
        void read();

        size_t addr_loc_raw();
        size_t addr_loc_end();
        size_t size();
        size_t addr_remote();

        size_t change_protection(DWORD prot);
        size_t make_writeable();
        size_t make_executable();
        size_t make_non_executable();
        size_t restore_prev_protection();
        HANDLE get_proc() { return m_proc; };

    private:
        HANDLE               m_proc = 0;
        size_t               m_addr_remote = 0;
        DWORD                m_old_prot = 0;
        DWORD                m_curr_prot = 0;
        bool                 m_is_local = false;

        // used only if m_is_local=true
        size_t               m_local_len = 0;

        // used only if m_is_local=false
        std::vector<uint8_t> m_data;


};

#endif // __MEMORY_TOOL_H

