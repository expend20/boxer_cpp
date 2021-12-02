#include "instrumenter.h"
#include "common.h"
#include "pe.h"

#include "say.h"
#include "tools.h"

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

void instrumenter::translate_all_bbs()
{
    SAY_INFO("Translating all basicblocks (could take a while)...\n");

    size_t mod_base = find_inst_module(*m_bbs.begin());
    ASSERT(mod_base);

    pehelper::section* code_sect = m_inst_mods[mod_base].code_sect;

    code_sect->data.begin();
    m_inst_mods[mod_base].inst.begin();

    auto code_sect_local = code_sect->data.addr_loc_raw();
    auto code_sect_remote = code_sect->data.addr_remote();

    auto shadow_sect = &m_inst_mods[mod_base].shadow;
    ASSERT(shadow_sect);
    auto shadow_sect_local = shadow_sect->addr_loc_raw();

    translator* trans = &m_inst_mods[mod_base].translator;
    for (auto &addr: m_bbs) {

        uint32_t inst_size = 0;
        uint32_t orig_size = 0;
        auto inst_addr = trans->translate(addr, &inst_size, &orig_size);
        ASSERT(inst_addr);
        if (orig_size < 2) {
            m_stats.bb_skipped_less_2++;
        }
        else if (orig_size < 5) {
            m_stats.bb_skipped_less_5++;
        }

        if (orig_size < 5) {
            //SAY_ERROR("BB at %p has size %d (inst %d), we need at "
            //        "least 5 to make jump\n", 
            //        addr, orig_size, inst_size);

            // NOTE: restoring the orig data, could be a solution
            // if we decide skip bbs 
            if (m_opts.skip_small_bb) {
                //SAY_INFO("skipping bb cov at %p...\n", addr);
                auto offset = addr - code_sect_remote;
                //SAY_INFO("restoring orig: %p %p %x\n",
                //        (void*)(code_sect->data.addr_loc() + offset),
                //        (void*)(shadow_sect->addr_loc() + offset),
                //        orig_size);
                memcpy((void*)(code_sect_local + offset),
                        (void*)(shadow_sect_local + offset),
                        orig_size);
            }
            //SAY_WARN("BB at %p has size %d (inst %d), is 1 byte"
            //        "long\n",
            //        addr, inst_size, orig_size);
        }
        else {
            // Place jump
            auto jump_size = trans->make_jump_from_orig_to_inst(
                    addr, inst_addr);
        }
    }
    if (m_opts.fix_dd_refs) 
        trans->fix_dd_refs();

    // Call commit on inst code
    code_sect->data.end();
    m_inst_mods[mod_base].inst.end();

    auto r = FlushInstructionCache(
            this->get_target_process(),
            (void*)code_sect->data.addr_remote(), 
            code_sect->data.size()
            );
    ASSERT(r);

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
        m_inst_mods[mod_base].inst.begin();

        if (m_opts.debug) 
            SAY_DEBUG("Address not found, instrumenting...\n");
        uint32_t inst_size = 0;
        uint32_t orig_size = 0;
        inst_addr = trans->translate(addr, &inst_size, &orig_size);
        ASSERT(inst_addr);
        if (m_opts.fix_dd_refs) 
            trans->fix_dd_refs();

        if (m_opts.is_bbs_inst ||
                m_opts.is_int3_inst_blind) {

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
                // if we decide skip bbs 
                if (m_opts.skip_small_bb && 
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
        m_inst_mods[mod_base].inst.end();

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

    //if (m_opts.debug) {
        SAY_INFO("Instrumenting %s %p %s...\n", inst_type, addr, name);
    //}

    if (m_inst_mods[addr].code_sect) 
        SAY_FATAL("Attempt to double instrument module at %p, %s\n",
                addr, name);

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
            auto offsets = helper::files2Vector(m_opts.bbs_path);
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
            PAGE_EXECUTE_READ);
    ASSERT(code_inst);
    auto mem_inst = mem_tool(hproc, code_inst, code_inst_size);
    mem_inst.read();
    m_inst_mods[addr].inst = mem_inst;

    // get coverage buffer
    size_t cov_buf_size = img_size;
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
            break;
        }
        case STATUS_STACK_OVERFLOW: {
            if (m_opts.debug)
                SAY_DEBUG("Got STATUS_STACK_OVERFLOW, ignoring...\n");
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
            "[ %d exceptions | %d avs | %d breakpoints ] \n"
            "\t %d pc redirections\n"

            "\t %d translated bb, skipped [ %d <5 | %d <2 ] \n"
            "\t %d cmpcov [ %d cmp | %d test | %d sub ]\n",

            m_inst_mods.size(), m_stats.dbg_callbacks, m_stats.veh_callbacks,
            m_stats.exceptions, m_stats.breakpoints, m_stats.avs,
            m_stats.rip_redirections,

            cs.translated_bbs,
            m_stats.bb_skipped_less_5, m_stats.bb_skipped_less_2,

            cs.cmpcov_cmp + cs.cmpcov_sub + cs.cmpcov_test,
            cs.cmpcov_cmp, cs.cmpcov_sub, cs.cmpcov_test
            );
}
DWORD instrumenter::handle_veh(_EXCEPTION_POINTERS* ex_info) {
    m_stats.veh_callbacks++;
    m_ctx = ex_info->ContextRecord;
    auto res = EXCEPTION_CONTINUE_SEARCH;

#ifdef _WIN64
    size_t pc = m_ctx->Rip;
#else
    size_t pc = m_ctx->Eip;
#endif
    if (translate_or_redirect(pc)) {
        res = EXCEPTION_CONTINUE_EXECUTION;
    }

    m_ctx = 0;
    return res;
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
    auto data = it->second;
    if (!data.inst.size()) SAY_FATAL("Uninstrument called for not instrumented "
            "module %p %s\n", addr, data.module_name.c_str());
    SAY_INFO("Uninstrumenting module %p %s\n", addr, data.module_name.c_str());

    auto r = VirtualFreeEx(proc, (void*)data.inst.addr_remote(), 0, 
            MEM_RELEASE);
    if (!r) {
        SAY_FATAL("Can't free mem in %x proc, at %p:%x, err = %s\n",
                proc, data.inst.addr_remote(), data.inst.size(), 
                helper::getLastErrorAsString().c_str());
    }
    if (data.shadow.size()) {
        // restore code section
        data.code_sect->data.begin();
        memcpy((void*)data.shadow.addr_loc_raw(),
                (void*)data.code_sect->data.addr_loc_raw(), 
                data.shadow.size());
        data.code_sect->data.end();
        
        r = VirtualFreeEx(proc, (void*)data.shadow.addr_remote(), 0, 
                MEM_RELEASE);
        ASSERT(r);
    }
    r = VirtualFreeEx(proc, (void*)data.cov.addr_remote(), 0, MEM_RELEASE);
    ASSERT(r);
    r = VirtualFreeEx(proc, (void*)data.cmpcov.addr_remote(), 0, 
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
