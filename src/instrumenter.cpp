#include "instrumenter.h"
#include "common.h"
#include "pe.h"

#include "Say.h"
#include "tools.h"

bool instrumenter::should_translate(size_t addr) 
{
    for (auto &sect: m_sections_patched) {
        auto start = sect->data.addr_remote();
        auto end = start + sect->data.size();
        if (addr >= start && addr < end) {

            m_stats.rip_redirections++;
            if (m_opts.debug) 
                SAY_DEBUG("That's we patched the code %p\n", addr);
            // That's we've patched the code, let's check if it's already 
            // instrumented
            // FIXME: 0x1000 offset shouldn't be hardcoded
            size_t mod_base = 0;
            for (auto &m: m_modules) {
                if (m.get_remote_addr() == start - 0x1000) {
                    mod_base = start - 0x1000;
                    break;
                }
            }
            ASSERT(mod_base);

            auto trans = &m_base_to_translator[mod_base];
            ASSERT(trans);

            size_t inst_addr = trans->remote_orig_to_inst_bb(addr);
            if (!inst_addr) { 
                if (m_opts.debug) 
                    SAY_DEBUG("Address not found, instrumenting...\n");
                inst_addr = trans->instrument(addr);
                ASSERT(inst_addr);
                m_stats.translator_called++;
            }
            else {
            }

            // TODO: review all code with pid/tid references in mind
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
                SAY_INFO("Redirecting on exception %p -> %p; "
                        "rax/rcx/rdx/r8/r9/rsp/rbp/rsi/rdi "
                        "%p/%p/%p/%p/%p/%p/%p/%p/%p\n", 
                        addr,  inst_addr,
                        ctx.Rax, ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9,
                        ctx.Rsp, ctx.Rbp, ctx.Rsi, ctx.Rdi);
                if (m_opts.is_int3_inst) {
                    ASSERT(addr == ctx.Rip - 1);
                }
                else {
                    ASSERT(addr == ctx.Rip);
                }
            }

            if (m_opts.is_int3_inst) {
                // TODO: place jump if possible
                tools::update_thread_rip(hThread, inst_addr);
            }
            else {
                tools::update_thread_rip(hThread, inst_addr);
            }


            return true;
        }
    }
    return false;
}

void instrumenter::patch_references_to_section(pehelper::pe* module, 
        pehelper::section* target_section, 
        size_t shadow_sect_remote_start){
    for (auto i = 0; i < module->get_section_count(); i++) {
        auto sect = module->get_section_by_idx(i);

        size_t patches_in_sect = 0;
        // due to VirturtualSize this restriction is relaxed
        //ASSERT(sect->data.size() % sizeof(size_t) == 0);
        size_t idx_max = sect->data.size() / sizeof(size_t);
        size_t* data = (size_t*)sect->data.addr_loc();
        size_t remote_start = target_section->data.addr_remote();
        size_t remote_end = remote_start + target_section->data.size();
        for (size_t idx = 0; idx < idx_max; idx++) {
            size_t dd = data[idx];
            if (dd >= remote_start && dd < remote_end) {
                patches_in_sect++;
                size_t offset = dd - remote_start;
                size_t new_dd = shadow_sect_remote_start + offset;
                data[idx] = new_dd; 
                SAY_DEBUG("dq fixed %p[%p] = %p", 
                        remote_start + idx * sizeof(size_t),
                        dd,
                        new_dd);
            }
        }
        if (patches_in_sect) {
            sect->data.commit();
            SAY_DEBUG("\n");
        }
    }
}

// TODO: merge into instrument_module()
void instrumenter::instrument_module_int3(size_t addr, const char* name) 
{
    if (m_opts.debug) 
        SAY_INFO("Instrumenting (int3) %p %s...\n", addr, name);

    auto hproc = m_debugger->get_proc_info()->hProcess;
    auto obj = pehelper::pe(hproc, addr);
    m_modules.push_back(obj);
    auto pe = &m_modules[m_modules.size() - 1];

    auto opt_head = pe->get_nt_headers()->OptionalHeader;
    size_t img_size = opt_head.SizeOfImage;
    size_t img_end = pe->get_remote_addr() + img_size;

    auto code_section = pe->get_section(".text");
    if (!code_section) code_section = pe->get_section(".code");
    ASSERT(code_section);

    //code_section->data.make_non_executable();
    m_sections_patched.push_back(code_section);

    // create shadow memory
    size_t shadow_code_size = code_section->data.size();
    auto shadow_code_ptr = tools::alloc_after_pe_image(
            hproc,
            img_end,
            shadow_code_size,
            PAGE_READONLY);
    ASSERT(shadow_code_ptr);
	m_base_to_shadow[addr] = mem_tool(hproc, shadow_code_ptr, shadow_code_size);
    auto shadow_code_data = &m_base_to_shadow[addr];

    // copy text to shadow
    memcpy((void*)shadow_code_data->addr_loc(),
            (void*)code_section->data.addr_loc(), 
            shadow_code_data->size());
    if (m_opts.debug) 
        SAY_INFO("copied loc %p %p %x\n",
                (void*)shadow_code_data->addr_loc(),
                (void*)code_section->data.addr_loc(), 
                shadow_code_data->size());
    shadow_code_data->commit();

    // fill text with int3s
    memset((void*)code_section->data.addr_loc(), 
            0xcc,
            code_section->data.size());
    code_section->data.commit();
    
    // fix references to code from other sections
    //patch_references_to_section(pe, 
    //        code_section, shadow_code_data->addr_remote());

    // get instrumentation buffer
    size_t code_inst_size = img_size * 4;
    auto code_inst = tools::alloc_after_pe_image(
            hproc,
            shadow_code_ptr + shadow_code_size,
            code_inst_size,
            PAGE_EXECUTE_READ);
    ASSERT(code_inst);
    auto mem_inst = mem_tool(hproc, code_inst, code_inst_size);
    mem_inst.read();
    m_base_to_inst[addr] = mem_inst;

    // get coverage buffer
    size_t cov_buf_size = img_size;
    auto cov_buf = tools::alloc_after_pe_image(hproc, 
            code_inst + code_inst_size,
            cov_buf_size,
            PAGE_READWRITE);
    ASSERT(cov_buf);
    auto mem_cov = mem_tool(hproc, cov_buf, cov_buf_size);
    m_base_to_cov[addr] = mem_cov;

    // get metadata buffer
    size_t meta_buf_size = img_size;
    auto meta_buf = tools::alloc_after_pe_image(hproc,
            cov_buf + cov_buf_size,
            meta_buf_size,
            PAGE_READWRITE);
    ASSERT(meta_buf);
    m_base_to_cov[addr] = mem_cov;

    // check 2gb limit, for relative data access
    ASSERT((meta_buf + meta_buf_size) - addr < 0x7fffffff);

    auto trans = translator(&m_base_to_inst[addr],
            &m_base_to_cov[addr],
            &m_base_to_metadata[addr],
            shadow_code_data,
            code_section->data.addr_remote());

    if (m_opts.translator_debug)
        trans.set_debug();

    if (m_opts.translator_disasm)
        trans.set_disasm();

    if (m_opts.fix_dd_refs && !m_opts.translator_single_step)
        trans.set_fix_dd_refs();

    if (m_opts.translator_single_step)
        trans.set_single_step();

    m_base_to_translator[addr] = trans;
}

void instrumenter::instrument_module(size_t addr, const char* name) 
{
    if (m_opts.debug) 
        SAY_INFO("Instrumenting %p %s...\n", addr, name);

    // patch the code section
    auto hproc = m_debugger->get_proc_info()->hProcess;
    auto obj = pehelper::pe(hproc, addr);
    m_modules.push_back(obj);
    auto pe = &m_modules[m_modules.size() - 1];
    auto code_section = pe->get_section(".text");
    if (!code_section) code_section = pe->get_section(".code");
    ASSERT(code_section);
    code_section->data.make_non_executable();
    m_sections_patched.push_back(code_section);
    if (m_opts.debug) 
        SAY_DEBUG("code section local: %p %x\n", code_section->data.addr_loc(),
                code_section->data.size());

    // get instrumentation buffer
    auto opt_head = pe->get_nt_headers()->OptionalHeader;
    size_t img_size = opt_head.SizeOfImage;
    size_t img_end = pe->get_remote_addr() + img_size;
    size_t code_inst_size = img_size * 4;
    auto code_inst = tools::alloc_after_pe_image(
            hproc,
            img_end,
            code_inst_size,
            PAGE_EXECUTE_READ);
    ASSERT(code_inst);
    auto mem_inst = mem_tool(hproc, code_inst, code_inst_size);
    mem_inst.read();
    m_base_to_inst[addr] = mem_inst;

    // get coverage buffer
    size_t cov_buf_size = img_size;
    auto cov_buf = tools::alloc_after_pe_image(hproc, 
            code_inst + code_inst_size,
            cov_buf_size,
            PAGE_READWRITE);
    ASSERT(cov_buf);
    auto mem_cov = mem_tool(hproc, cov_buf, cov_buf_size);
    m_base_to_cov[addr] = mem_cov;

    // get metadata buffer
    size_t meta_buf_size = img_size;
    auto meta_buf = tools::alloc_after_pe_image(hproc,
            cov_buf + cov_buf_size,
            meta_buf_size,
            PAGE_READWRITE);
    ASSERT(meta_buf);
    m_base_to_cov[addr] = mem_cov;

    // check 2gb limit, for relative data access
    ASSERT((meta_buf + meta_buf_size) - addr < 0x7fffffff);

    auto trans = translator(&m_base_to_inst[addr],
            &m_base_to_cov[addr],
            &m_base_to_metadata[addr],
            &code_section->data,
            code_section->data.addr_remote());

    if (m_opts.translator_debug)
        trans.set_debug();

    if (m_opts.translator_disasm)
        trans.set_disasm();

    if (m_opts.fix_dd_refs && !m_opts.translator_single_step)
        trans.set_fix_dd_refs();

    if (m_opts.translator_single_step)
        trans.set_single_step();

    m_base_to_translator[addr] = trans;
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

void instrumenter::on_first_breakpoint()
{
    if (m_opts.debug) 
        SAY_INFO("on_first_breakpoint() reached\n");
    for (auto &[addr, mod_name]: m_remote_modules_list) {
        if (should_instrument_module(mod_name.c_str()))
            if (m_opts.is_int3_inst) {
                instrument_module_int3(addr, mod_name.c_str());
            }
            else {
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
                "Exception event: code %x | %s | %s, addr %p, flags %x, params %x"
                ", is_int3 %d, dd_fix %d\n",
                rec->ExceptionCode,
                tools::get_exception_name(rec->ExceptionCode).c_str(),
                dbg_info->dwFirstChance ? "first chance" : "second chance",
                rec->ExceptionAddress,
                rec->ExceptionFlags,
                rec->NumberParameters,
                m_opts.is_int3_inst,
                m_opts.fix_dd_refs);

        for (uint32_t i = 0; i < rec->NumberParameters; i++) {
            SAY_DEBUG("\tEx info %d: %p\n", i, rec->ExceptionInformation[i]);
        }
    }
    if (!dbg_info->dwFirstChance) {
        SAY_ERROR("Second chance exception caught, exiting...\n");

        {
            auto pi = m_debugger->get_proc_info();
            tools::write_minidump("second_chance.dmp",
                    pi,
                    &dbg_info->ExceptionRecord);
        }

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
                if (!m_opts.is_int3_inst &&
                        should_translate(rec->ExceptionInformation[1]))
                    continue_status = DBG_CONTINUE;
            }
            break;
        }
        case STATUS_BREAKPOINT: {
            m_stats.breakpoints++;
            if (m_stats.breakpoints == 1) {
                // if it's first breakpoint, it's debugger's one
                on_first_breakpoint();
            } else {
                if (m_opts.is_int3_inst &&
                        should_translate((size_t)rec->ExceptionAddress)) {
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
            // TODO:
            SAY_ERROR("Invalid exception code %x\n",
                    rec->ExceptionCode);
        }
    }
    return continue_status;
}

void instrumenter::print_stats() 
{
    SAY_INFO("Instrumenter stats: \n"
            "%20d dbg_callbaks\n"
            "%20d exceptions\n"
            "%20d breakpoints\n"
            "%20d avs\n"
            "%20d translator_called\n"
            "%20d rip_redirections\n",
            m_stats.dbg_callbaks,
            m_stats.exceptions,
            m_stats.breakpoints,
            m_stats.avs,
            m_stats.translator_called,
            m_stats.rip_redirections
            );
}

DWORD instrumenter::handle_debug_event(DEBUG_EVENT* dbg_event,
        debugger* debugger)
{
    if (m_opts.debug) {
        SAY_DEBUG("Instrumentor::handle_debug_event: %x / %x\n", 
                dbg_event->dwDebugEventCode,
                m_stats.dbg_callbaks);
        //if (m_stats.dbg_callbaks > 0x10000) {
        //    // TODO:
        //    {
        //        SAY_INFO("Stopping at %x iteration\n", m_stats.dbg_callbaks);
        //        auto pi = m_debugger->get_proc_info();
        //        tools::write_minidump("exit_process.dmp", pi, NULL);
        //        print_stats();
        //        m_debugger->stop();
        //    }
        //}
    }
    m_debugger = debugger;
    m_dbg_event = dbg_event;
    m_stats.dbg_callbaks++;
    auto continue_status = DBG_CONTINUE;//DBG_EXCEPTION_NOT_HANDLED;

    switch (dbg_event->dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateProcessInfo;
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
            if (m_opts.debug)
                SAY_DEBUG("Program loaded %p %s\n",
                        data.lpBaseOfImage,
                        mod_name.c_str());
            m_remote_modules_list[(size_t)data.lpBaseOfImage] = mod_name;

            CloseHandle(data.hFile);
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            continue_status = handle_exception(&dbg_event->u.Exception);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            auto data = dbg_event->u.LoadDll;

            // extract file name
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
            if (m_opts.debug)
                SAY_INFO("Module loaded %p %s\n",
                        data.lpBaseOfDll,
                        mod_name.c_str());
            m_remote_modules_list[(size_t)data.lpBaseOfDll] = mod_name;

            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT: {
            auto data = dbg_event->u.UnloadDll;
            if (m_opts.debug) {
                SAY_INFO("Module unloaded %p\n", data.lpBaseOfDll);
            }
            break;
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
        }
        case EXIT_THREAD_DEBUG_EVENT: {
            auto data = dbg_event->u.ExitThread;
            if (m_opts.debug)
                SAY_INFO("Exit thread: %x\n", data.dwExitCode);
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.ExitProcess;
            if (m_opts.debug) 
                SAY_INFO("Exiting process with %d\n", data.dwExitCode);
            // TODO: 
            {
                auto pi = m_debugger->get_proc_info();
                tools::write_minidump("exit_process.dmp", pi, NULL);
                print_stats();
            }
            m_debugger->stop();
            break;
        }
        case OUTPUT_DEBUG_STRING_EVENT: {
            auto data = dbg_event->u.DebugString;
            if (m_opts.debug)  {
                SAY_INFO("Debug string event (is unicode %d, len = %d) %p\n", 
                        data.fUnicode,
                        data.nDebugStringLength,
                        data.lpDebugStringData);
                auto str = mem_tool(m_debugger->get_proc_info()->hProcess,
                        (size_t)data.lpDebugStringData,
                        data.fUnicode ? data.nDebugStringLength * 2:
                        data.nDebugStringLength);
                if (data.fUnicode) {
                    SAY_INFO("OutputDebugStringW called: %S\n", 
                            (void*)str.addr_loc());
                }
                else {
                    SAY_INFO("OutputDebugStringA called: %s\n", 
                            (void*)str.addr_loc());
                }
            }
            break;
        }
        default:
            SAY_WARN("Unhandled debug event: %x\n", 
                    dbg_event->dwDebugEventCode);
    }
    return continue_status;
};
