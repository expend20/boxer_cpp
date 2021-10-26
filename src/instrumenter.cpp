#include "instrumenter.h"
#include "pe.h"

#include "Say.h"
#include "tools.h"

bool instrumenter::should_handle_dep_av(size_t addr) 
{
    for (auto &sect: m_sections_patched) {
        auto start = sect->data.addr_remote();
        auto end = start + sect->data.size();
        SAY_DEBUG("addr %p ? %p %p\n", addr, start, end);
        if (addr >= start && addr < end) {

            SAY_ERROR("That's we patched the code!\n");
            // That's we've patched the code, let's check if it's already 
            // instrumented
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
            ASSERT(trans->m_inst_code && trans->m_cov_buf && trans->m_metadata);

            size_t inst_addr = trans->remote_to_inst(addr);
            if (!inst_addr) { 
                SAY_ERROR("Address not found, instrumenting...\n");
                inst_addr = trans->instrument(addr);
                ASSERT(inst_addr);
            }

            // TODO: debug only branch
            {
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_ALL;
                auto r = GetThreadContext(m_debugger->get_proc_info()->hThread,
                        &ctx);
                ASSERT(r);
                SAY_DEBUG("threads rip: %p\n", ctx.Rip);
            }

            tools::update_thread_rip(m_debugger->get_proc_info()->hThread,
                    inst_addr);
            // TODO: realizy if we really need that
            //r = FlushInstructionCache(
            //        m_debugger->get_proc_info()->hProcess, (void*)(addr-1), 2);
            //ASSERT(r);


            return true;
        }
    }
    return false;
}

void instrumenter::instrument_module(size_t addr, const char* name) 
{
    LOG_DEBUG("Instrumenting %p %s...\n", addr, name);

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

    // 4gb limit, for relative data access
    ASSERT((meta_buf + meta_buf_size) - addr < 0xffffffff);

    m_base_to_translator[addr] = translator(&m_base_to_inst[addr],
            &m_base_to_cov[addr],
            &m_base_to_metadata[addr]);
}

void instrumenter::should_instrument_modules()
{
    for (auto& mod_to_inst: m_modules_to_instrument) {
        for (auto& [addr, name]: m_remote_modules_list) {
            if (!_stricmp(mod_to_inst.c_str(), name.c_str())) {
                instrument_module(addr, name.c_str());
            }
        }
    }
}

void instrumenter::add_module(const char* name) 
{
    m_modules_to_instrument.push_back(std::string(name));
}

void instrumenter::on_first_breakpoint()
{
    LOG_INFO("on_first_breakpoint() reached\n");

    should_instrument_modules();

}

DWORD instrumenter::handle_exception(EXCEPTION_DEBUG_INFO* dbg_info)
{
    m_stats.exceptions++;
    auto rec = &dbg_info->ExceptionRecord;

    SAY_DEBUG(
            "Exception event: code %x | %s | %s, addr %p, flags %x, params %x\n",
            rec->ExceptionCode,
            tools::get_exception_name(rec->ExceptionCode).c_str(),
            dbg_info->dwFirstChance ? "first chance" : "second chance",
            rec->ExceptionAddress,
            rec->ExceptionFlags,
            rec->NumberParameters);
    for (uint32_t i = 0; i < rec->NumberParameters; i++) {
        SAY_DEBUG("\tEx info %d: %p\n", i, rec->ExceptionInformation[i]);
    }
    if (!dbg_info->dwFirstChance) {
        SAY_ERROR("Second chance exception caught, exiting...\n");

        {
            auto pi = m_debugger->get_proc_info();
            tools::write_minidump("second_chance.dmp",
                    pi,
                    &dbg_info->ExceptionRecord);
        }

        exit(0);
    }
    auto continue_status = DBG_EXCEPTION_NOT_HANDLED;
    switch (rec->ExceptionCode) {
        case STATUS_ACCESS_VIOLATION: {
            m_stats.avs++;
            if (rec->NumberParameters == 2 &&
                    rec->ExceptionInformation[0] == 8 && // DEP
                    rec->ExceptionInformation[1]) {
                if (should_handle_dep_av(rec->ExceptionInformation[1]))
                    continue_status = DBG_CONTINUE;
            }
            break;
        }
        case STATUS_BREAKPOINT: {
            m_stats.breakpoints++;
            if (m_stats.breakpoints == 1) {
                // if it's first breakpoint, it's debugger's one
                on_first_breakpoint();
            }
            break;
        }
        default: {
            SAY_FATAL("Invalid exception code %x",
                    rec->ExceptionCode);
        }
    }
    return continue_status;
}

DWORD instrumenter::handle_debug_event(DEBUG_EVENT* dbg_event,
        debugger* debugger)
{
    SAY_DEBUG("instrumentor::handle_debug_event: %x\n", 
            dbg_event->dwDebugEventCode);
    m_debugger = debugger;
    m_stats.dbg_callbaks++;
    auto continue_status = DBG_EXCEPTION_HANDLED;

    switch (dbg_event->dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateProcessInfo;
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
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
            SAY_DEBUG("Module loaded %p %s\n",
                    data.lpBaseOfDll,
                    mod_name.c_str());
            m_remote_modules_list[(size_t)data.lpBaseOfDll] = mod_name;
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateThread;
            SAY_DEBUG("Create thread: %x, base %p, start %p\n",
                    data.hThread,
                    data.lpThreadLocalBase,
                    data.lpStartAddress);
            __debugbreak();
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.ExitProcess;
            SAY_INFO("Exiting process with %d\n", data.dwExitCode);
            m_debugger->stop();
            break;
        }
        default:
            SAY_WARN("Unhandled debug event: %x\n", dbg_event->dwDebugEventCode);
    }
    return continue_status;
};
