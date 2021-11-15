#include "debugger.h"
#include "say.h"
#include "common.h"

#include <strsafe.h>
#include <psapi.h>

debugger::debugger(const char* cmd_line, 
        uint32_t flags)
{
    STARTUPINFO si = {0};
    si.cb = sizeof(si);

    char cmd_args[265];

    auto r = StringCchCopy(cmd_args, sizeof(cmd_args), cmd_line);
    if (r != S_OK) SAY_FATAL("Can't copy sting: %s", cmd_line);

    DWORD creation_flags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;
    if (!CreateProcessA(NULL,
                cmd_args,
                NULL,
                NULL,
                FALSE,
                flags,
                NULL,
                NULL,
                &si,
                &m_pi)
       ){
        SAY_FATAL("Can't create process: %s, %s\n",
                cmd_line,
                helper::getLastErrorAsString().c_str());
    }

    SAY_INFO("Process %s created %d:%d\n", cmd_line, m_pi.dwProcessId, 
            m_pi.dwThreadId);
    CloseHandle(m_pi.hProcess);
    m_pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, m_pi.dwProcessId);
    ASSERT(m_pi.hProcess);

};

debugger::~debugger() {
    CloseHandle(m_pi.hProcess);
    CloseHandle(m_pi.hThread);
}

void debugger::run(size_t steps) {

    //if (!m_handler) SAY_FATAL("Run attempt without handler registered");

    for (size_t i = 0; i < steps; i++) {
        if (m_stopped) break;

        WaitForDebugEvent(&m_debug_event, INFINITE);
        m_events_count++;

        auto continue_status =
            m_handler->handle_debug_event(&m_debug_event, this);

        // TODO: debug only
        switch (continue_status) {
            case DBG_CONTINUE:
                SAY_DEBUG("sending DBG_CONTINUE\n");
                break;
            case DBG_EXCEPTION_HANDLED:
                SAY_DEBUG("sending DBG_EXCEPTION_HANDLED\n");
                break;
            case DBG_EXCEPTION_NOT_HANDLED:
                SAY_DEBUG("sending DBG_EXCEPTION_NOT_HANDLED\n");
                break;
            default:
                SAY_DEBUG("sending uknown continue status %x\n", 
                        continue_status);
        }
        ContinueDebugEvent(m_debug_event.dwProcessId,
                m_debug_event.dwThreadId,
                continue_status);

    }
}
