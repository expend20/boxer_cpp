#include "mem_tool.h"
#include "common.h"
#include "say.h"

#include <memoryapi.h>

bool mem_tool::is_in_rage_remote(size_t addr){
    if (addr >= m_addr_remote && addr < (m_addr_remote + m_data.size())) {
        return true;
    } else {
        return false;
    }
}

size_t mem_tool::get_bytes_left_by_addr(size_t addr) {
    ASSERT(addr >= m_addr_remote);
    if (addr - m_addr_remote >= m_data.size()) __debugbreak();
    ASSERT(addr - m_addr_remote < m_data.size());
    return m_addr_remote + m_data.size() - addr;
}

size_t mem_tool::get_mem_by_addr(size_t addr) {
    ASSERT(addr >= m_addr_remote);
    ASSERT(addr - m_addr_remote < m_data.size());
    if (addr >= m_addr_remote && (addr - m_addr_remote < m_data.size())) {
        return (size_t)&m_data[addr - m_addr_remote];
    } else {
        return 0;
    }
}

size_t mem_tool::get_tgt_by_offset(size_t offset){
    ASSERT(offset < m_data.size());
    return (size_t)(m_addr_remote + offset);
}

size_t mem_tool::get_tgt_by_local(size_t loc){
    ASSERT(loc >= (size_t)&m_data[0]);
    ASSERT(loc < (size_t)&m_data[m_data.size() - 1]);
        return -1;

    return get_tgt_by_offset(loc - (size_t)&m_data[0]);
}

size_t mem_tool::get_mem_by_offset(size_t offset) {
    ASSERT(offset < m_data.size());
    return (size_t)&m_data[offset];
}

size_t mem_tool::addr_remote() {
    return m_addr_remote;
}
size_t mem_tool::size() {
    if (m_is_local) 
        return m_local_len;
    else
        return m_data.size();
}

size_t mem_tool::addr_loc_raw() {
    if (m_is_local) return m_addr_remote;
    return (size_t)&m_data[0];
}

void mem_tool::begin() {
    if (m_is_local) {
        change_protection(PAGE_READWRITE);
    }
}

size_t mem_tool::begin_addr_loc() {
    // Here we start the transaction and return local address
    if (m_is_local) {
        begin();
        return m_addr_remote;
    }
    else {
        // just return the copy to a pointer
        return (size_t)&m_data[0];
    }
}

void mem_tool::end() {
    if (m_is_local) {
        restore_prev_protection();
    }
    else {
        commit_remote();
    }
}

size_t mem_tool::addr_loc_end() {
    if (m_is_local) {
        return m_local_len + m_addr_remote;
    }
    else {
        return (size_t)&m_data[0] + m_data.size();
    }
}

void mem_tool::read() {
    SIZE_T rw = 0;

    if (!ReadProcessMemory(m_proc, (void*)m_addr_remote, &m_data[0], 
                m_data.size(), &rw)){
        SAY_FATAL("can't read process memory %x %p %x\n",
                m_proc, m_addr_remote, m_data.size());
    }

    ASSERT(rw == m_data.size());
    //SAY_DEBUG("Process %x memory read %p:%x -> %p:%x\n", m_proc, m_addr,
    //        m_data.size(), &m_data[0], rw);
}

mem_tool::mem_tool(HANDLE process, size_t data, size_t len) {

    ASSERT(process);
    ASSERT(data);
    ASSERT(len);

    if (GetCurrentProcess() == process) {
        m_is_local = true;
        m_local_len = len;
    }
    else {
        // we don't need the copy for local process
        m_data.resize(len);
    }

    m_addr_remote = data;
    m_proc = process;

    read();
}

void mem_tool::commit_remote() {

    if (m_is_local) return; 

    SIZE_T rw = 0;

    change_protection(PAGE_READWRITE);

    if (!WriteProcessMemory(m_proc, (void*)m_addr_remote, &m_data[0], 
                m_data.size(), &rw)){
        SAY_FATAL("Can't write process memory %x %p -> %p %x, err = %s\n",
                m_proc, &m_data[0], m_addr_remote, m_data.size(),
                helper::getLastErrorAsString().c_str());
    }

    restore_prev_protection();

    ASSERT(rw == m_data.size());
}


size_t mem_tool::change_protection(DWORD prot){

    auto sz = m_is_local ? m_local_len : m_data.size();
    ASSERT(sz != 0);

    if (!VirtualProtectEx(m_proc, (void*)m_addr_remote, sz,
                prot, &m_old_prot)) {
        SAY_FATAL("Can't protect memory %p:%x, err %s", m_addr_remote,
                sz, helper::getLastErrorAsString().c_str());
    } else {

        SAY_DEBUG("Section %p:%x changed protection from %x to %x\n",
                m_addr_remote, sz, m_old_prot, prot);
    }

    return 0;
}

size_t mem_tool::restore_prev_protection(){
    DWORD new_prot = 0;
    auto sz = m_is_local ? m_local_len : m_data.size();
    ASSERT(sz != 0);

    SAY_DEBUG("Restoring section protection %x %p:%p\n", m_old_prot,
            m_addr_remote, sz);

    BOOL res = VirtualProtectEx(m_proc, (void*)m_addr_remote, sz, 
            m_old_prot, &new_prot);
    if (!res) {
        SAY_FATAL("Can't restore memory prot %p:%x, err %s", m_addr_remote,
                sz, helper::getLastErrorAsString().c_str());
    }

    m_old_prot = new_prot;
    return 0;

}

size_t mem_tool::make_writeable(){
    return change_protection(PAGE_READWRITE);
}

size_t mem_tool::make_non_executable(){
    return change_protection(PAGE_READONLY);
}

size_t mem_tool::make_executable(){
    return change_protection(PAGE_EXECUTE_READ);
}

