#include "instrumenter.h"
#include "common.h"
#include "pe.h"

#include "say.h"
#include "tools.h"

#define MAGIC_OFFSET_STORE 7
#define MAGIC_OFFSET_CONTINUE 4

#include <string.h>

#include <psapi.h>

void instrumenter::clear_leaks() 
{
    m_leaks.free_all();
}

std::vector<strcmp_data>* instrumenter::get_strcmpcov()
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }
    return m_strcmpcov.get_data();
}

void instrumenter::clear_strcmpcov() 
{
    m_strcmpcov.clear_data();
}

void instrumenter::install_strcmpcov() 
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }
    auto it = m_inst_mods.begin();
    auto mod = &(it->second);

    auto imports = mod->pe.get_imports();
    m_strcmpcov.install(imports);
}

void instrumenter::uninstall_strcmpcov() 
{
    m_strcmpcov.uninstall();
}

void instrumenter::install_leaks() 
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }
    auto it = m_inst_mods.begin();
    auto mod = &(it->second);

    auto imports = mod->pe.get_imports();
    m_leaks.install(imports);
}

void instrumenter::uninstall_leaks() 
{
    m_leaks.uninstall();
}

void instrumenter::clear_cov()
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }
    auto it = m_inst_mods.begin();
    auto mod = &(it->second);
    auto addr = mod->cov.begin_addr_loc();
    auto sz = mod->cov.size();
    memset((void*)addr, 0, sz);
    mod->cov.end();
}

void instrumenter::clear_passed_cmpcov_code()
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }
    
    auto mod = &(m_inst_mods.begin()->second);
    auto data = (uint8_t*)mod->cmpcov.begin_addr_loc();
    auto ci = mod->translator.get_cmpcov_info();
    auto offset = mod->translator.get_cmpcov_offset();
    bool unlocked = false;
    for (uint32_t i = 0; i < offset; i++) {
        if (data[i] && 
                (*ci)[i].all_bits && 
                data[i] == (*ci)[i].all_bits) {

            data[i] = 0;

            if (!unlocked) {
                // FIXME: inst section is RWX for now
                //mod->inst.make_writeable();
                unlocked = true;
            }

            //SAY_INFO("Let's clear cmp %x %p %p\n", i, (*ci)[i].start, 
            //        (*ci)[i].end);
            mod->translator.make_jump_from_inst_to_inst((*ci)[i].start, 
                    (*ci)[i].end);
            m_stats.cmpcov_cleaned++;
        }
    }
    // FIXME: inst section is RWX for now
    if (unlocked) mod->inst.restore_prev_protection();
    mod->cmpcov.end();
}

void instrumenter::clear_cmpcov()
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }
    auto mod = &(m_inst_mods.begin()->second);
    memset((void*)mod->cmpcov.begin_addr_loc(), 0, 
            mod->translator.get_cmpcov_offset());
    mod->cmpcov.end();
}

uint8_t* instrumenter::get_cov(uint32_t* size)
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }

    auto mod = &(m_inst_mods.begin()->second);
    mod->cov.read();
    uint8_t* res = (uint8_t*)mod->cov.addr_loc_raw();
    if (size) 
        *size = (uint32_t)mod->cov.size();

    return res;
}

uint8_t* instrumenter::get_cmpcov(uint32_t* size)
{
    if (m_inst_mods.size() != 1) {
        SAY_FATAL("Only one inst module is currently supported, got %d\n", 
                m_inst_mods.size());
    }

    auto mod = &(m_inst_mods.begin()->second);
    mod->cmpcov.read();
    uint8_t* res = (uint8_t*)mod->cmpcov.addr_loc_raw();
    if (size) 
        *size = (uint32_t)mod->translator.get_cmpcov_offset();

    static bool is_shown = false;
    if (!is_shown) {
        SAY_INFO("cmpcov size %d\n", mod->translator.get_cmpcov_offset());
        is_shown = true;
    }

    return res;
}

HANDLE instrumenter::get_target_process()
{
    HANDLE res = INVALID_HANDLE_VALUE;
    if (m_debugger) {
        res = m_debugger->get_proc_info()->hProcess;
    } else {
        res = GetCurrentProcess();
    }
    return res;
}

size_t instrumenter::find_inst_module_by_inst_addr(size_t addr)
{
    for (auto &[mod_base, mod_data]: m_inst_mods) {

        if (!mod_data.code_sect) continue;

        auto start = mod_data.inst.addr_remote();
        auto end = start + mod_data.inst.size();
        if (addr >= start && addr < end) {
            return mod_base;
        }
    }
    return 0;

}

size_t instrumenter::find_inst_module(size_t addr)
{
    for (auto &[mod_base, mod_data]: m_inst_mods) {

        if (!mod_data.code_sect) continue;

        auto start = mod_data.code_sect->data.addr_remote();
        auto end = start + mod_data.code_sect->data.size();
        if (addr >= start && addr < end) {
            return mod_base;
        }
    }
    return 0;
}

void instrumenter::fix_two_bytes_bbs(translator* trans, 
        std::map<size_t, instrumenter_bb_info>* bbs_info, 
        std::vector<size_t>* two_bytes_bbs)
{
    for (auto addr_two_bytes: *two_bytes_bbs) {
        auto our_it = bbs_info->find(addr_two_bytes);
        auto our_end = addr_two_bytes + 2;
        auto our_begin = addr_two_bytes;

        //SAY_INFO("translating %p\n", addr_two_bytes);

        size_t ptr_five_bytes = 0;
        auto i = 0;
        for (auto it = std::prev(our_it, 1);
                i < 40 && it != bbs_info->end(); 
                i++, it = std::prev(it, 1)) {
            auto p_base = it->first;
            auto p_orig_size = it->second.orig_size;
            auto p_bytes_left = p_orig_size - it->second.bytes_taken;
            //SAY_INFO("Trying %p %d(%d)\n", p_base, p_orig_size, p_bytes_left);

            if (p_bytes_left < 5) {
                //SAY_INFO("not valid (short %d) %p %d\n", p_bytes_left,
                //        p_base, p_orig_size);
                continue;
            }
            auto new_addr = p_base + p_orig_size - 5;
            if (our_end - new_addr >= 0x80) {
                //SAY_INFO("not valid (far %d) %p %d(%d)\n", 
                //        our_end - new_addr,
                //        p_base, p_orig_size, p_bytes_left);
                break;
            }
            ptr_five_bytes = new_addr;
            //SAY_INFO("valid new: %p (%p %d(%d))\n", ptr_five_bytes, p_base,
            //        p_orig_size, p_bytes_left);
            it->second.orig_size -= 5;

            // place 2 jumps
            size_t inst_addr = trans->remote_orig_to_inst_bb(addr_two_bytes);
            ASSERT(inst_addr);
            trans->make_jump_from_orig_to_inst(ptr_five_bytes, inst_addr);
            trans->make_1byte_jump_from_orig_to_orig(addr_two_bytes, 
                    ptr_five_bytes);
            //SAY_INFO("%p %p %p\n", addr_two_bytes, ptr_five_bytes, inst_addr);

            break;
        }
        if (ptr_five_bytes) continue;
        //SAY_INFO("backward search: not found\n");

        i = 0;
        for (auto it = std::next(our_it, 1); 
                i < 40 && it != bbs_info->begin(); 
                i++, it = std::next(it, 1)) {
            auto n_base = it->first;
            auto n_orig_size = it->second.orig_size;
            auto n_bytes_left = n_orig_size - it->second.bytes_taken;
            if (n_bytes_left < 5) {
                //SAY_INFO("not valid (short %d) %p %d\n", 
                //        next->first - curr_end,
                //        it->first, it->second);
                continue;
            }
            auto new_addr = n_base + it->second.bytes_taken;
            if (new_addr - our_end >= 0x80) {
                //SAY_INFO("not valid (far %d) %p %d\n", 
                //        curr_end - our_end,
                //        it->first, it->second);
                break;
            }

            ptr_five_bytes = new_addr;
            it->second.bytes_taken += 5;
            // place 2 jumps
            size_t inst_addr = trans->remote_orig_to_inst_bb(addr_two_bytes);
            ASSERT(inst_addr);
            trans->make_jump_from_orig_to_inst(ptr_five_bytes, inst_addr);
            trans->make_1byte_jump_from_orig_to_orig(addr_two_bytes, 
                    ptr_five_bytes);
            break;
        }
        if (ptr_five_bytes) continue;

        //SAY_INFO("forward search: not found\n");
        //SAY_INFO("can't patch <5 byte basic block at %p:%d\n", 
        //        addr_two_bytes, 2);
        m_stats.bb_skipped_less_5++;
    }
}

void instrumenter::translate_all_bbs()
{
    SAY_INFO("Translating all basicblocks (could take a while)...\n");

    size_t mod_base = find_inst_module(*m_bbs.begin());
    ASSERT(mod_base);

    pehelper::section* code_sect = m_inst_mods[mod_base].code_sect;

    code_sect->data.begin();
    // FIXME: inst is RWX for now
    //m_inst_mods[mod_base].inst.begin();

    auto code_sect_local = code_sect->data.addr_loc_raw();
    auto code_sect_remote = code_sect->data.addr_remote();

    auto shadow_sect = &m_inst_mods[mod_base].shadow;
    ASSERT(shadow_sect);
    auto shadow_sect_local = shadow_sect->addr_loc_raw();

    translator* trans = &m_inst_mods[mod_base].translator;

    uint32_t prev_vec_size = 20;

    std::vector<size_t> two_bytes_bbs;
    
    for (auto &addr: m_bbs) {

        uint32_t inst_size = 0;
        uint32_t orig_size = 0;
        auto inst_addr = trans->translate(addr, &inst_size, &orig_size);
        m_bbs_info[addr].orig_size = orig_size;
        ASSERT(inst_addr);

        if (m_opts.show_flow) continue;
        //if (!m_opts.fix_dd_refs) continue; // don't fix jump in this mode

        if (orig_size >= 5) {
            // Place jump
            auto jump_size = trans->make_jump_from_orig_to_inst(
                    addr, inst_addr);
            ASSERT(jump_size == 5);
            m_bbs_info[addr].bytes_taken = jump_size;

        } 
        else if (orig_size < 5 && orig_size >= 2) {
            // add to second pass
            m_bbs_info[addr].bytes_taken = 2;
            two_bytes_bbs.push_back(addr);
        }
        else if (orig_size < 2) {
            // quick check for nop
            auto offset_code = addr - code_sect_remote;
            //SAY_INFO("%p [%p:%p]\n", addr, 
            if (*(uint8_t*)(shadow_sect_local + offset_code) == 0x90) {
                *(uint8_t*)(code_sect_local + offset_code) = 0x90;
            }
            else {
                // nothing much we can do here
                // if we decide skip bbs 
                m_stats.bb_skipped_less_2++;
                if (m_opts.skip_small_bb) {
                    auto offset = addr - code_sect_remote;
                    memcpy((void*)(code_sect_local + offset),
                            (void*)(shadow_sect_local + offset),
                            orig_size);
                }
            }
        }

        
        // NOTE: restoring the orig data, could be a solution
        // if we decide to skip bbs 
        if (orig_size < 5 && m_opts.skip_small_bb && 
                m_inst_mods[mod_base].shadow.size()
           ) {
            //SAY_INFO("skipping bb cov at %p...\n", addr);
            auto shadow_sect = &m_inst_mods[mod_base].shadow;
            auto offset = addr - code_sect->data.addr_remote();
            //SAY_INFO("restoring orig: %p %p %x",
            //        (void*)(sect->data.addr_loc() + offset),
            //        (void*)(shadow_sect->addr_loc() + offset),
            //        orig_size);
            memcpy((void*)(code_sect->data.addr_loc_raw() + offset),
                    (void*)(shadow_sect->addr_loc_raw() + offset),
                    orig_size);
        }
    }

    if (!m_opts.show_flow) {
        SAY_INFO("Fixing dd refs...\n");
        if (m_opts.fix_dd_refs) 
            trans->fix_dd_refs();

        SAY_INFO("Fixing two bytes bb...\n");
        fix_two_bytes_bbs(trans, &m_bbs_info, &two_bytes_bbs);
    }

    // Call commit on inst code
    code_sect->data.end();
    // FIXME: inst is RWX for now
    //m_inst_mods[mod_base].inst.end(); 

    //auto r = FlushInstructionCache(
    //        this->get_target_process(),
    //        (void*)code_sect->data.addr_remote(), 
    //        code_sect->data.size()
    //        );
    //ASSERT(r);

    SAY_INFO("All bbs translation done...\n");
}

void instrumenter::redirect_execution(size_t addr, size_t inst_addr) 
{
    if (m_opts.show_flow) {
#ifdef _WIN64
        SAY_INFO("Redirecting on exception %p -> %p;\n", addr,  inst_addr);
#else 
        SAY_INFO("Redirecting on exception %p -> %p;\n", addr,  inst_addr);
#endif
    }

    if (m_debugger) {
        auto hThread = m_tid_to_handle[m_dbg_event->dwThreadId];
        if (!hThread) {
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, 
                    m_dbg_event->dwThreadId);
            ASSERT(hThread);
            m_tid_to_handle[m_dbg_event->dwThreadId] = hThread;
        }
        if (m_opts.debug || m_opts.show_flow) 
        {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            auto r = GetThreadContext(hThread, &ctx);
            ASSERT(r);

            if (m_opts.is_int3_inst_blind || m_opts.is_bbs_inst) {
#ifdef _WIN64
                ASSERT(addr == ctx.Rip - 1);
#else
                ASSERT(addr == ctx.Eip - 1);
#endif
            }
            else {
#ifdef _WIN64
                ASSERT(addr == ctx.Rip);
#else
                ASSERT(addr == ctx.Eip);
#endif
            }
        }

        tools::update_thread_rip(hThread, inst_addr);
    }
    else {
        ASSERT(m_ctx);
#ifdef _WIN64
        if (m_ctx->Rip - addr > 1)
            SAY_FATAL("Weird pc / exception address: %p / %p\n", m_ctx->Rip,
                    addr);
        m_ctx->Rip = inst_addr;
#else
        if (m_ctx->Eip - addr > 1)
            SAY_FATAL("Weird pc / exception address: %p / %p\n", m_ctx->Eip,
                    addr);
        m_ctx->Eip = inst_addr;
#endif
    }
}

void instrumenter::handle_crash(uint32_t code, size_t addr)
{
    auto mod_base = find_inst_module_by_inst_addr(addr);
    if (mod_base) {
        m_crash_info.mod_name = m_inst_mods[mod_base].module_name;
        // TODO: fix to orig offset:
        m_crash_info.offset = addr - m_inst_mods[mod_base].inst.addr_remote(); 
    }
    else {
        // not instrumented module
        HMODULE mods[1024];
        DWORD cb;
        uint32_t i;
        char mod_name[MAX_PATH];

        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cb)){
            SAY_FATAL("Can't list modules on crash: %s\n", 
                    helper::getLastErrorAsString().c_str());
        }

        for (i = 0; i < (cb / sizeof(HMODULE)); i++) {
            MODULEINFO mi = {0};
            auto r = GetModuleInformation(GetCurrentProcess(), mods[i],
                    &mi, sizeof(mi));
            if (!r) {
                SAY_FATAL("Can't get module %p info: %s\n", mods[i],
                        helper::getLastErrorAsString().c_str());
            }

            if (addr >= (size_t)mi.lpBaseOfDll && 
                    addr <= (size_t)mi.lpBaseOfDll + mi.SizeOfImage) {
                // we found the module
            }
            else {
                continue;
            }

            r = GetModuleBaseName(GetCurrentProcess(), mods[i],
                    mod_name, sizeof(mod_name));
            if (!r) {
                SAY_FATAL("Can't get module %p base name: %s\n", mods[i],
                        helper::getLastErrorAsString().c_str());
            }

            m_crash_info.mod_name = mod_name;
            m_crash_info.offset = addr - (size_t)mods[i];
            SAY_INFO("Handling the crash: %s %x %x\n", mod_name, 
                    m_crash_info.offset, code);
            break;
        }

        if (i == cb / sizeof(HMODULE)) {
            SAY_ERROR("Can't locate module %p\n", addr);

            m_crash_info.mod_name = "unk";
            m_crash_info.offset = addr;
        }

        //{
        //    char buf[512];
        //    snprintf(buf, sizeof(buf), "%s_%x.dump", 
        //            m_crash_info.mod_name.c_str(),
        //            code);

        //    SAY_INFO("Writing minidump: %s\n", buf);
        //    tools::write_minidump(buf, GetCurrentProcess());
        //    __debugbreak();
        //}
    }
    m_crash_info.code = code;
}

bool instrumenter::translate_or_redirect(size_t addr) 
{
    auto mod_base = find_inst_module(addr);
    if (!mod_base) return false;
    auto code_sect = m_inst_mods[mod_base].code_sect;
    ASSERT(code_sect);

    m_stats.rip_redirections++;
    if (m_opts.debug) 
        SAY_DEBUG("That's we patched the code %p\n", addr);
    // That's we've patched the code, let's check if it's already 
    // instrumented

    auto trans = &m_inst_mods[mod_base].translator;
    ASSERT(trans);

    size_t inst_addr = trans->remote_orig_to_inst_bb(addr);
    if (!inst_addr) { 
        // FIXME: it's RWX for now
        //m_inst_mods[mod_base].inst.begin();

        if (m_opts.debug) 
            SAY_DEBUG("Address not found, instrumenting...\n");
        uint32_t inst_size = 0;
        uint32_t orig_size = 0;
        inst_addr = trans->translate(addr, &inst_size, &orig_size);
        ASSERT(inst_addr);
        if (m_opts.fix_dd_refs) {
            trans->fix_dd_refs();
        }
        if ((m_opts.is_bbs_inst || m_opts.is_int3_inst_blind) && 
                m_opts.fix_dd_refs) {

            if (orig_size < 5) {
                m_stats.bb_skipped_less_5++;
            } else if (orig_size < 2) {
                m_stats.bb_skipped_less_2++;
            }

            code_sect->data.begin();
            if (orig_size < 5) {
                //SAY_ERROR("BB at %p has size %d (inst %d), we need at "
                //        "least 5 to make jump\n", 
                //        addr, orig_size, inst_size);

                // NOTE: restoring the orig data, could be a solution
                // if we decide to skip bbs 
                if (m_opts.skip_small_bb && 
                        m_inst_mods[mod_base].shadow.size()
                   ) {
                    // SAY_INFO("skipping bb cov at %p...\n", addr);
                    auto shadow_sect = &m_inst_mods[mod_base].shadow;
                    auto offset = addr - code_sect->data.addr_remote();
                    //SAY_INFO("restoring orig: %p %p %x",
                    //        (void*)(sect->data.addr_loc() + offset),
                    //        (void*)(shadow_sect->addr_loc() + offset),
                    //        orig_size);
                    memcpy((void*)(code_sect->data.addr_loc_raw() + offset),
                            (void*)(shadow_sect->addr_loc_raw() + offset),
                            orig_size);
                }
                //if (orig_size < 2) 
                //    SAY_WARN("BB at %p has size %d (inst %d), is 1 byte"
                //            "long\n",
                //            addr, inst_size, orig_size);
            }
            else {
                // Place jump
                auto jump_size = trans->make_jump_from_orig_to_inst(
                        addr, inst_addr);
                // Commit on orig code
                auto r = FlushInstructionCache(
                        get_target_process(),
                        (void*)addr, jump_size
                        );
                ASSERT(r);
            }
            code_sect->data.end();
        }

        // Call commit on inst code
        // FIXME: it's RWX for now
        //m_inst_mods[mod_base].inst.end();

        auto r = FlushInstructionCache(
                get_target_process(),
                (void*)inst_addr, inst_size
                );
        ASSERT(r);
    }

    redirect_execution(addr, inst_addr);
    return true;
}

void instrumenter::instrument_module(size_t addr, const char* name) 
{
    auto inst_type = "dep";
    if (m_opts.is_bbs_inst) {
        inst_type = "bbs";
    } else {
        inst_type = "int3";
    }

    SAY_INFO("Instrumenting %s %p %s...\n", inst_type, addr, name);
    SAY_INFO("Covbuf size = %x\n", m_opts.covbuf_size);

    if (m_inst_mods[addr].code_sect) 
        SAY_FATAL("Attempt to double instrument module at %p, %s\n",
                addr, name);

    m_inst_mods[addr].module_name = name;
    
    auto hproc = this->get_target_process();
    m_inst_mods[addr].pe = pehelper::pe(hproc, addr);
    auto pe = &m_inst_mods[addr].pe;

    auto opt_head = pe->get_nt_headers()->OptionalHeader;
    size_t img_size = opt_head.SizeOfImage;
    size_t img_end = pe->get_remote_addr() + img_size;

    auto code_section = pe->get_section(".text");
    if (!code_section) code_section = pe->get_section(".code");
    ASSERT(code_section);
    m_inst_mods[addr].code_sect = code_section;

    mem_tool* shadow_code_data = 0;

    if (m_opts.is_bbs_inst || m_opts.is_int3_inst_blind) {
        // create shadow memory
        size_t shadow_code_size = code_section->data.size();
        auto shadow_code_ptr = tools::alloc_after_pe_image(
                hproc,
                img_end,
                shadow_code_size,
                PAGE_READWRITE);
        ASSERT(shadow_code_ptr);
        m_inst_mods[addr].shadow = mem_tool(hproc, shadow_code_ptr, 
                shadow_code_size);
        shadow_code_data = &m_inst_mods[addr].shadow;

        // copy text to shadow
        memcpy((void*)shadow_code_data->addr_loc_raw(),
                (void*)code_section->data.addr_loc_raw(), 
                shadow_code_data->size());
        if (m_opts.debug) 
            SAY_INFO("copied loc %p %p %x\n",
                    (void*)shadow_code_data->addr_loc_raw(),
                    (void*)code_section->data.addr_loc_raw(), 
                    shadow_code_data->size());

        code_section->data.begin();
        if (m_opts.is_bbs_inst) {
            // fill text with int3s based on bbs file
            auto offsets = helper::files_to_vector(m_opts.bbs_path);
            if (!offsets.size()) {
                SAY_FATAL("Check file path %s, int's invalid\n",
                        m_opts.bbs_path);
            }
            uint32_t* ptr = (uint32_t*)&offsets[0][0];
            size_t offsets_not_in_code = 0;
            for (size_t i = 0; i < offsets[0].size() / 4; i++) {
                uint32_t sect_offset = ptr[i] - 
                    code_section->sect_head.VirtualAddress;
                if (sect_offset >= code_section->data.size()) {
                    offsets_not_in_code++;
                    continue;
                }
                m_bbs.insert(ptr[i] + addr);
                *(uint8_t*)(code_section->data.addr_loc_raw() + 
                        sect_offset) = 0xcc;
            }
            SAY_INFO("%d offsets patched to int3\n", 
                    offsets[0].size() - offsets_not_in_code);
            if (offsets_not_in_code) {
                SAY_WARN("%d offsets were poiting not in the code section, they"
                        " are skipped\n", offsets_not_in_code);
            }

        }
        if (m_opts.is_int3_inst_blind) {
            // fill all the text section with int3s
            memset((void*)code_section->data.addr_loc_raw(), 
                    0xcc,
                    code_section->data.size());
        }

        code_section->data.end();
        img_end = shadow_code_ptr + shadow_code_size;
    }
    else { 
        // dep mode
        code_section->data.make_non_executable();
    }

    // get instrumentation buffer
    size_t code_inst_size = img_size * 4;
    auto code_inst = tools::alloc_after_pe_image(
            hproc,
            img_end,
            code_inst_size,
            PAGE_EXECUTE_READWRITE);
            // FIXME: ^ inst section is RWX for now
            //PAGE_EXECUTE_READ);
    ASSERT(code_inst);
    auto mem_inst = mem_tool(hproc, code_inst, code_inst_size);
    mem_inst.read();
    m_inst_mods[addr].inst = mem_inst;

    // get coverage buffer
    size_t cov_buf_size = m_opts.covbuf_size;
    auto cov_buf = tools::alloc_after_pe_image(hproc, 
            code_inst + code_inst_size,
            cov_buf_size,
            PAGE_READWRITE);
    ASSERT(cov_buf);
    auto mem_cov = mem_tool(hproc, cov_buf, cov_buf_size);
    m_inst_mods[addr].cov = mem_cov;

    // get metadata buffer
    size_t meta_buf_size = img_size;
    auto meta_buf = tools::alloc_after_pe_image(hproc,
            cov_buf + cov_buf_size,
            meta_buf_size,
            PAGE_READWRITE);
    ASSERT(meta_buf);
    auto mem_meta = mem_tool(hproc, meta_buf, meta_buf_size);
    SAY_INFO("remote cmpcov %p\n", mem_meta.addr_remote());
    m_inst_mods[addr].cmpcov = mem_meta;

    // check 2gb limit, for relative data access
    ASSERT((meta_buf + meta_buf_size) - addr < 0x7fffffff);

    auto trans = translator(&m_inst_mods[addr].inst,
            &m_inst_mods[addr].cov,
            &m_inst_mods[addr].cmpcov,
            &code_section->data,
            code_section->data.addr_remote());

    if (shadow_code_data) trans.set_shadow_code(shadow_code_data);
    if (m_bbs.size()) trans.set_bbs(&m_bbs);

    if (m_opts.call_to_jump) {
        trans.set_call_to_jump();
    }

    if (m_opts.translator_debug)
        trans.set_debug();

    if (m_opts.translator_disasm)
        trans.set_disasm();

    if (m_opts.translator_single_step)
        trans.set_single_step();

    if (m_opts.translator_cmpcov)
        trans.set_cmpcov();

    m_inst_mods[addr].translator = trans;

    if (m_opts.is_bbs_inst_all &&
            m_bbs.size()) {
        translate_all_bbs();
    }

}

bool instrumenter::should_instrument_module(const char* name)
{
    for (auto& mod_to_inst: m_modules_to_instrument) {
        if (!_stricmp(mod_to_inst.c_str(), name)) {
            return true;
        }
    }
    return false;
}

void instrumenter::add_module(const char* name) 
{
    if (m_opts.debug) 
        SAY_INFO("We'll instrument module %s\n", name);
    m_modules_to_instrument.push_back(std::string(name));
}

void instrumenter::explicit_instrument_module(size_t addr, const char* name) {
    instrument_module(addr, name);
}

void instrumenter::on_first_breakpoint()
{
    // From this moment we can instrument modules actually, but they could
    // be loaded already, so enumerate all the loaded modules and instrument
    // them if we should
    if (m_opts.debug) 
        SAY_INFO("on_first_breakpoint() reached\n");

    for (auto &[addr, mod_name]: m_loaded_mods) {
        if (m_inst_mods.find(addr) == m_inst_mods.end() &&
                should_instrument_module(mod_name.c_str())) {
            instrument_module(addr, mod_name.c_str());
        }
    }
}

DWORD instrumenter::handle_exception(EXCEPTION_DEBUG_INFO* dbg_info)
{
    m_stats.exceptions++;
    auto rec = &dbg_info->ExceptionRecord;

    if (m_stats.exceptions % 5000 == 0) {
        print_stats();
    }

    if (m_opts.debug || !dbg_info->dwFirstChance) {
        SAY_INFO(
                "Exception event: code %x | %s | %s, addr %p, flags %x, params "
                "%x, is_int3 %d, dd_fix %d\n",
                rec->ExceptionCode,
                tools::get_exception_name(rec->ExceptionCode).c_str(),
                dbg_info->dwFirstChance ? "first chance" : "second chance",
                rec->ExceptionAddress,
                rec->ExceptionFlags,
                rec->NumberParameters,
                m_opts.is_int3_inst_blind,
                m_opts.fix_dd_refs);

        for (uint32_t i = 0; i < rec->NumberParameters; i++) {
            SAY_INFO("\tEx info %d: %p\n", i, rec->ExceptionInformation[i]);
        }
    }
    if (!dbg_info->dwFirstChance) {
        SAY_ERROR("Second chance exception caught, exiting...\n");

        tools::write_minidump("second_chance.dmp", get_target_process());
        print_stats();
        exit(0);
    }
    auto continue_status = DBG_EXCEPTION_NOT_HANDLED;
    switch (rec->ExceptionCode) {
        case STATUS_ACCESS_VIOLATION: {
            m_stats.avs++;
            if (rec->NumberParameters == 2 &&
                    rec->ExceptionInformation[0] == 8 && // DEP
                    rec->ExceptionInformation[1]) {
                if (!m_opts.is_int3_inst_blind && !m_opts.is_bbs_inst &&
                        translate_or_redirect(rec->ExceptionInformation[1]))
                    continue_status = DBG_CONTINUE;
            }
            break;
        }
        case STATUS_BREAKPOINT: {
            m_stats.breakpoints++;
            if (m_stats.breakpoints == 1) {
                // if it's first breakpoint, it's debugger's one
                on_first_breakpoint();
                m_first_breakpoint_reached = true;
                continue_status = DBG_CONTINUE;
            } else {
                if (//(m_opts.is_int3_inst || m_opts.is_bbs_inst) &&
                        translate_or_redirect((size_t)rec->ExceptionAddress)) {
                    continue_status = DBG_CONTINUE;
                }
            }

            __debugbreak();
            // TODO: store context
            //if (*(uint32_t*)((size_t)rec->ExceptionAddress + 
            //            MAGIC_OFFSET_STORE) == MARKER_STORE_CONTEXT) {
            //    SAY_INFO("PC for continuation on exception %p\n", 
            //            rec->ExceptionAddress);
            //    //memcpy(&m_restore_ctx, m_ctx, sizeof(m_restore_ctx));
            //}
            break;
        }
        case STATUS_STACK_OVERFLOW: {
            if (m_opts.debug)
                SAY_DEBUG("Got STATUS_STACK_OVERFLOW, ignoring...\n");
            break;
        }
        case DBG_PRINTEXCEPTION_C: {
            m_stats.output_debug_str++;
            break;
        }
        default: {
            SAY_ERROR("Invalid exception code %x\n",
                    rec->ExceptionCode);
        }
    }
    return continue_status;
}

void instrumenter::print_stats() 
{
    translator_stats cs = {0};
    for (auto &[addr, data]: m_inst_mods) {
        auto s = data.translator.get_stats();
        cs.cmpcov_cmp += s->cmpcov_cmp;
        cs.cmpcov_sub += s->cmpcov_sub;
        cs.cmpcov_test += s->cmpcov_test;
        cs.translated_bbs += s->translated_bbs;
    }
    SAY_INFO("Instrumenter stats: \n"
            "\t %d modules, callbacks [ %d dbg | %d veh ] "
            "[ %d exceptions | %d avs | %d breakpoints | %d c++eh | %d dbgstr ]"
            "\n"
            "\t %d pc redirections\n"

            "\t %d translated bb, skipped [ %d <5 | %d <2 ] \n"
            "\t %d cmpcov [ %d cmp | %d test | %d sub ] %d cleaned\n",

            m_inst_mods.size(), m_stats.dbg_callbacks, m_stats.veh_callbacks,

            m_stats.exceptions, m_stats.breakpoints, m_stats.avs,
            m_stats.cpp_exceptions, m_stats.output_debug_str,

            m_stats.rip_redirections,

            cs.translated_bbs,
            m_stats.bb_skipped_less_5, m_stats.bb_skipped_less_2,

            cs.cmpcov_cmp + cs.cmpcov_sub + cs.cmpcov_test,
            cs.cmpcov_cmp, cs.cmpcov_sub, cs.cmpcov_test,
            m_stats.cmpcov_cleaned
            );
}

void instrumenter::adjust_restore_context() {

    if (!m_pc_restore_addr) {
#ifdef _WIN64
        auto pc = m_restore_ctx.Rip;
#else
        auto pc = m_restore_ctx.Eip;
#endif

        for (uint32_t i = 0; i < 64; i++) {
            if ( *(uint8_t*)(pc + i) == 0xe8 &&
                   *(uint8_t*)(pc + i + 5) == 0x90) {
                m_pc_restore_addr = pc + i + 5;
                break;
            }
        }

        if (!m_pc_restore_addr) {
            SAY_FATAL("Can't find magic at %p + 100\n", pc);
        }
        //SAY_INFO("PC set %p -> %p\n", pc, m_pc_restore_addr);
    }

#ifdef _WIN64
    //SAY_INFO("PC use %p -> %p\n", m_restore_ctx.Rip, m_pc_restore_addr);
    m_restore_ctx.Rip = m_pc_restore_addr;
#else
    //SAY_INFO("PC use %p -> %p\n", m_restore_ctx.Eip, m_pc_restore_addr);
    m_restore_ctx.Eip = m_pc_restore_addr;
#endif
    m_restore_ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
}

DWORD instrumenter::handle_veh(_EXCEPTION_POINTERS* ex_info) {
    m_stats.veh_callbacks++;
    m_ctx = ex_info->ContextRecord;
    auto res = 0;

#ifdef _WIN64
    size_t pc = m_ctx->Rip;
#else
    size_t pc = m_ctx->Eip;
#endif

    //if (m_opts.debug) {
    //    SAY_INFO("Instrumentor::handle_veh: %x %x, vehs %x, ctx %x\n", 
    //            ex_info->ExceptionRecord->ExceptionCode,
    //            pc,
    //            m_stats.veh_callbacks,
    //            m_ctx);
    //}

    bool should_translate_or_redirect = false;
    bool processed = false;
    auto ex_record = ex_info->ExceptionRecord;
    auto ex_code = ex_record->ExceptionCode;
    do { 
        // check for instrumenations and breaks
        switch (ex_code) {
            case STATUS_ACCESS_VIOLATION:
                if (ex_record->NumberParameters == 2 &&
                        ex_record->ExceptionInformation[0] == 8 && // DEP
                        ex_record->ExceptionInformation[1]) {
                    should_translate_or_redirect = true;
                }
                break;
            case STATUS_BREAKPOINT:

                should_translate_or_redirect = true;

        }
        if (res) break;

        if (!res && should_translate_or_redirect && translate_or_redirect(pc)) {
            res = 1;
            break;
        }

#ifdef _WIN64
        // check for c++ exceptions
        if (ex_code == 0xe06d7363 ||
                // windowscodecs.dll jpeg_error_mgr::error_exit:
                ex_code == 0xc0000002 ||
                // msxml6!Exception::throwStored:
                ex_code == 0xe0000001){ 
            m_stats.cpp_exceptions++;
            //SAY_WARN("C++ exception: .exr %p, at %p\n",
            //        ex_info->ExceptionRecord, 
            //        ex_info->ExceptionRecord->ExceptionAddress);
            if (m_restore_ctx.Rip) {
            //if (m_restore_ctx.Eip) {
                adjust_restore_context();
                // restore previously saved context
                memcpy(m_ctx, &m_restore_ctx, sizeof(*m_ctx));
                res = 1;
                break;
            }
            else { 
                SAY_FATAL("C++ exception happened, but context was not "
                        "stored\n");
            }
        }
#endif

        // Last resort, probably crashed
        switch (ex_code) {

            case STATUS_STACK_OVERFLOW:
                SAY_WARN("Stack exhausted, exception %x\n", ex_code);
                SAY_WARN("We can't really handle stack exhausting bugs without "
                        "restarting of the process (which is slow), so just "
                        "save the crashing sample and stop for now :(\n");
                // The reason behind this is next. If stack is exhausted, the
                // kernel allocates more stack (only once) and continues the
                // execution with that exception. If it happens second time
                // AV will be generated, and exception handling will become 
                // impossible because there will be no more stack growth.
                handle_crash(ex_code, pc);
                ExitProcess(-1);
                break;
            case STATUS_ACCESS_VIOLATION:

                SAY_INFO("av ctx %p\n", m_ctx);
                handle_crash(ex_code, pc);
                __debugbreak();
#ifdef _WIN64
                if (m_restore_ctx.Rip) {
#else 
                if (m_restore_ctx.Eip) {
#endif

                    adjust_restore_context();
                    //SAY_INFO("Crash ctx %p, restore ctx %p\n", m_ctx,
                    //        &m_restore_ctx);
                    
                    // restore previously saved context
                    if (!m_ctx) SAY_FATAL("m_ctx is zero\n");
                    memcpy(m_ctx, &m_restore_ctx, sizeof(*m_ctx));
                }
                else { 
                    SAY_FATAL("Crash happened, but context was not stored %p\n",
                            &m_restore_ctx);
                }
                res = 1;
                break;

            case DBG_PRINTEXCEPTION_C || DBG_PRINTEXCEPTION_WIDE_C:
                m_stats.output_debug_str++;
                res = 1;
                break;
        }


    } while(0);

    m_ctx = 0;
    if (ex_code == STATUS_STACK_OVERFLOW)
        printf("stack overflow ret\n");
    return res == 0 ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_CONTINUE_EXECUTION;
}

DWORD instrumenter::handle_debug_event(DEBUG_EVENT* dbg_event,
        debugger* debugger)
{
    if (m_opts.debug) {
        SAY_DEBUG("Instrumentor::handle_debug_event: %x / %x\n", 
                dbg_event->dwDebugEventCode,
                m_stats.dbg_callbacks);
    }
    if (m_opts.stop_at &&
            m_stats.dbg_callbacks >= m_opts.stop_at) {
        SAY_INFO("Stopping at iteration # %d\n", m_stats.dbg_callbacks);
        tools::write_minidump("stop_at.dmp", get_target_process());
        print_stats();
        m_debugger->stop();
    }

    m_debugger = debugger;
    m_dbg_event = dbg_event;

    m_stats.dbg_callbacks++;
    auto continue_status = DBG_EXCEPTION_NOT_HANDLED;

    switch (dbg_event->dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateProcessInfo;
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
            auto mod_base = (size_t)data.lpBaseOfImage;
            if (m_opts.debug)
                SAY_DEBUG("Program loaded %p %s\n",
                        mod_base,
                        mod_name.c_str());
            m_loaded_mods[mod_base] = mod_name;

            CloseHandle(data.hFile);
            continue_status = DBG_CONTINUE;
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.ExitProcess;
            //if (m_opts.debug10 
                SAY_INFO("Exiting process with %d\n", data.dwExitCode);
            // Creating dump on exitprocess
            {
                auto pi = debugger->get_proc_info();
                tools::write_minidump("exit_process.dmp", get_target_process());
                print_stats();
            }
            debugger->stop();
            uninstrument_all();
            continue_status = DBG_CONTINUE;
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            continue_status = handle_exception(&dbg_event->u.Exception);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            auto data = dbg_event->u.LoadDll;
            auto mod_base = (size_t)data.lpBaseOfDll;

            // extract file name && add to loaded list
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
            if (m_opts.debug)
                SAY_INFO("Module loaded %p %s\n",
                        data.lpBaseOfDll,
                        mod_name.c_str());
            m_loaded_mods[mod_base] = mod_name;

            // We instrument module on loading only after first breakpoint
            // was reached, otherwise we could interfere with system's dll
            // loading mechanism (e.g. during kernelbase.dll instrumentation)
            if (m_first_breakpoint_reached &&
                    should_instrument_module(mod_name.c_str()) &&
                    m_inst_mods.find(mod_base) == m_inst_mods.end()){
                instrument_module((size_t)data.lpBaseOfDll, mod_name.c_str());
            }
            continue_status = DBG_CONTINUE;
            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT: {
            auto data = dbg_event->u.UnloadDll;
            auto mod_base = (size_t)data.lpBaseOfDll;

            // uninstrument module
            if (m_inst_mods.find(mod_base) != m_inst_mods.end()) {
                SAY_WARN("Unloading instrumented module %p %s\n", mod_base,
                        m_inst_mods[mod_base].module_name.c_str());
                uninstrument(mod_base);
            }

            // remove module from loaded list
            auto it = m_loaded_mods.find(mod_base);
            ASSERT(it != m_loaded_mods.end());
            if (m_opts.debug) {
                SAY_INFO("Module unloading %p %s\n", mod_base, 
                        m_loaded_mods[mod_base].c_str());
            }

            m_loaded_mods.erase(it);

            continue_status = DBG_CONTINUE;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateThread;
            if (m_opts.debug) {
                SAY_INFO("Create thread: %x, base %p, start %p\n",
                        data.hThread,
                        data.lpThreadLocalBase,
                        data.lpStartAddress);
            }
            break;
            continue_status = DBG_CONTINUE;
        }
        case EXIT_THREAD_DEBUG_EVENT: {
            auto data = dbg_event->u.ExitThread;
            if (m_opts.debug)
                SAY_INFO("Exit thread: %x\n", data.dwExitCode);
            break;
            continue_status = DBG_CONTINUE;
        }
        case OUTPUT_DEBUG_STRING_EVENT: {
            auto data = dbg_event->u.DebugString;
            if (m_opts.debug)  {
                SAY_INFO("Debug string event (is unicode %d, len = %d) %p\n", 
                        data.fUnicode,
                        data.nDebugStringLength,
                        data.lpDebugStringData);
                auto str = mem_tool(debugger->get_proc_info()->hProcess,
                        (size_t)data.lpDebugStringData,
                        data.fUnicode ? data.nDebugStringLength * 2:
                        data.nDebugStringLength);
                if (data.fUnicode) {
                    SAY_INFO("OutputDebugStringW called: %S\n", 
                            (void*)str.addr_loc_raw());
                }
                else {
                    SAY_INFO("OutputDebugStringA called: %s\n", 
                            (void*)str.addr_loc_raw());
                }
            }
            continue_status = DBG_CONTINUE;
            break;
        }
        default:
            SAY_WARN("Unhandled debug event: %x\n", 
                    dbg_event->dwDebugEventCode);
    }
    return continue_status;
};

void instrumenter::uninstrument(size_t addr)
{
    auto it = m_inst_mods.find(addr);
    if (it == m_inst_mods.end()) return;

    auto proc = get_target_process();
    auto data = &(it->second);
    if (!data->inst.size()) {
        SAY_FATAL("Uninstrument called for not instrumented "
            "module %p %s\n", addr, data->module_name.c_str());
    }
    SAY_INFO("Uninstrumenting module %p %s\n", addr, data->module_name.c_str());

    auto r = VirtualFreeEx(proc, (void*)data->inst.addr_remote(), 0, 
            MEM_RELEASE);
    if (!r) {
        SAY_FATAL("Can't free mem in %x proc, at %p:%x, err = %s\n",
                proc, data->inst.addr_remote(), data->inst.size(), 
                helper::getLastErrorAsString().c_str());
    }
    if (data->shadow.size()) {
        // restore code section
        data->code_sect->data.begin();
        memcpy((void*)data->code_sect->data.addr_loc_raw(), 
                (void*)data->shadow.addr_loc_raw(),
                data->shadow.size());
        data->code_sect->data.end();
        
        r = VirtualFreeEx(proc, (void*)data->shadow.addr_remote(), 0, 
                MEM_RELEASE);
        ASSERT(r);
    }
    else {
        data->code_sect->data.restore_prev_protection();
    }
    r = VirtualFreeEx(proc, (void*)data->cov.addr_remote(), 0, MEM_RELEASE);
    ASSERT(r);
    r = VirtualFreeEx(proc, (void*)data->cmpcov.addr_remote(), 0, 
            MEM_RELEASE);
    ASSERT(r);
    m_inst_mods.erase(it);
}

void instrumenter::uninstrument_all() 
{
    // it's better not to modify the map while iterating it
    std::vector<size_t> bases_to_uninst; 
    for (auto &[mod_base, data]: m_inst_mods) {
        bases_to_uninst.push_back(mod_base);
    }
    for (auto &base: bases_to_uninst)
        uninstrument(base);

}

instrumenter::instrumenter() {
}

instrumenter::~instrumenter() {
}
