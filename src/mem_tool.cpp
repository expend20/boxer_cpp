#include "mem_tool.h"
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
    return m_data.size();
}

size_t mem_tool::addr_loc() {
    return (size_t)&m_data[0];
}

size_t mem_tool::addr_loc_end() {
    return (size_t)&m_data[0] + m_data.size();
}

void mem_tool::read() {
    size_t rw = 0;

    if (!ReadProcessMemory(m_proc, (void*)m_addr_remote, &m_data[0], m_data.size(),
                &rw)){
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

    m_addr_remote = data;
    m_proc = process;

    m_data.resize(len);

    read();
}

void mem_tool::commit() {
    size_t rw = 0;

    if (!WriteProcessMemory(m_proc, (void*)m_addr_remote, &m_data[0], m_data.size(),
                &rw)){
        SAY_FATAL("can't write process memory %x %p %x\n",
                m_proc, m_addr_remote, m_data.size());
    }

    ASSERT(rw == m_data.size());
}


size_t mem_tool::change_protection(DWORD prot){

    auto sz = m_data.size();
    ASSERT(sz != 0);

    if (!VirtualProtectEx(m_proc, (void*)m_addr_remote, m_data.size(),
                prot, &m_oldProt)) {
        SAY_FATAL("Can't protect memory %p:%x", m_addr_remote,
                m_data.size());
        return -1;
    } else {

        SAY_DEBUG("section %p:%x changed protection from %x to %x\n",
                m_addr_remote, m_data.size(), m_oldProt, prot);
    }

    return 0;
}

size_t mem_tool::restore_prev_protection(){
    DWORD newProt = 0;

    SAY_DEBUG("restoring section protection %x %p:%p\n", m_oldProt,
            m_addr_remote, m_data.size());

    BOOL res = VirtualProtect((void*)m_addr_remote, m_data.size(), m_oldProt,
            &newProt);
    ASSERT(res);

    m_oldProt = newProt;
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

