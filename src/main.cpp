#include "Say.h"
#include "common.h"

#include <strsafe.h>
#include <psapi.h>

#include "debugger.h"

#include <map>
#include <string>

namespace tools {

    std::string get_path_by_handle(HANDLE handle) 
    {
        char mod_name[MAX_PATH];
        auto max_chars = GetFinalPathNameByHandleA(
                handle, 
                mod_name, 
                sizeof(mod_name), 
                0);
        if (!max_chars) SAY_FATAL("Can't get file path by handle %x", handle);
        std::string s = mod_name;
        return s;
    };

    std::string get_path_by_mod_name(const char* path, size_t max_chars) 
    {
        size_t i;
        for (i = max_chars; i != 0; i--) {
            if (path[i - 1] == '\\') break;
        }
        std::string s = &path[i];
        return s;
    };

    std::string get_mod_name_by_handle(HANDLE handle) 
    {
        auto path = tools::get_path_by_handle(handle);
        auto s = tools::get_path_by_mod_name(path.c_str(), path.size());
        return s;
    }
};

struct InstrumentorStats {
    size_t dbg_callbaks;
    size_t exceptions;
    size_t breakpoints;
    size_t avs;
};

class Instrumentor: public IDebugHandler {

    public:
        Instrumentor() {};
        DWORD HandleDebugEvent(DEBUG_EVENT* dbg_event,
                Debugger* debuger) override;

    private:

        DWORD HandleException(EXCEPTION_DEBUG_INFO* dbg_info,
                Debugger* debugger);
        void OnFirstBreakpoint(Debugger* debugger);

    private:

        InstrumentorStats m_stats = {0};
        std::map<size_t, std::string> m_modules;


};

void Instrumentor::OnFirstBreakpoint(Debugger* debugger)
{
    // patch all the modules
    LOG_DEBUG("OnFirstBreakpoint() reached\n");

}

DWORD Instrumentor::HandleException(EXCEPTION_DEBUG_INFO* dbg_info,
        Debugger* debugger)
{
    m_stats.exceptions++;
    auto rec = &dbg_info->ExceptionRecord;

    SAY_DEBUG(
            "Exception event: code %x, addr %x, flags %x, params %x\n",
            rec->ExceptionCode,
            rec->ExceptionAddress,
            rec->ExceptionFlags,
            rec->NumberParameters);
    for (auto i = 0; i < rec->NumberParameters; i++) {
        SAY_DEBUG("Ex info %d: %x\n", i, rec->ExceptionInformation[i]);
    }

    switch (rec->ExceptionCode) {
        case STATUS_ACCESS_VIOLATION: {
            m_stats.avs++;

        }
        case STATUS_BREAKPOINT: {
            m_stats.breakpoints++;
            if (m_stats.breakpoints == 1) {
                // if it's first breakpoint, it's debugger's one
                OnFirstBreakpoint(debugger);
            }
            break;
        }
        default: {
            SAY_FATAL("Invalid exception code %x",
                    rec->ExceptionCode);
        }
    }
}

DWORD Instrumentor::HandleDebugEvent(DEBUG_EVENT* dbg_event,
        Debugger* debugger)
{
    SAY_DEBUG("Instrumentor::HandleDebugEvent: %x\n", 
            dbg_event->dwDebugEventCode);
    m_stats.dbg_callbaks++;
    auto continue_status = DBG_CONTINUE;

    switch (dbg_event->dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateProcessInfo;
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
            SAY_DEBUG("Program loaded %p %s\n",
                    data.lpBaseOfImage,
                    mod_name.c_str());
            m_modules[(size_t)data.lpBaseOfImage] = mod_name;
            CloseHandle(data.hFile);
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            continue_status = HandleException(&dbg_event->u.Exception, 
                    debugger);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            auto data = dbg_event->u.LoadDll;

            // extract file name
            auto mod_name = tools::get_mod_name_by_handle(data.hFile);
            SAY_DEBUG("module loaded %p %s\n",
                    data.lpBaseOfDll,
                    mod_name.c_str());
            m_modules[(size_t)data.lpBaseOfDll] = mod_name;
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            auto data = dbg_event->u.CreateThread;
            SAY_DEBUG("Create thread: %x, base %p, start %p",
                    data.hThread,
                    data.lpThreadLocalBase,
                    data.lpStartAddress);
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            auto data = dbg_event->u.ExitProcess;
            SAY_INFO("Exit process %d", data.dwExitCode);
            debugger->Stop();
            break;
        }
        default:
            SAY_WARN("Unhandled debug event: %x\n", dbg_event->dwDebugEventCode);
    }
    return DBG_CONTINUE;
};

int main(int argc, const char** argv) {
    
    InitLogs(argc, argv);
    SAY_INFO("Hello %s", "world\n");

    auto dbg = Debugger("..\\program.exe", 
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);

    auto ins = Instrumentor();
    //ins.AddModule("program.exe");
    
    dbg.RegisterHandler(&ins);
    dbg.Run(10);

    return -1;
}
