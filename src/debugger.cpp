#include "debugger.h"
#include "say.h"
#include "common.h"

#include <strsafe.h>
#include <psapi.h>

Debugger::Debugger(const char* cmd_line, 
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
        SAY_FATAL("Can't create process: %s, %s",
                cmd_line,
                helper::getLastErrorAsString().c_str());
    }

    CloseHandle(m_pi.hProcess);
};

Debugger::~Debugger() {
    CloseHandle(m_pi.hProcess);
    CloseHandle(m_pi.hThread);
}

void Debugger::Run(size_t steps) {

    //if (!m_handler) SAY_FATAL("Run attempt without handler registered");

    for (size_t i = 0; i < steps; i++) {
        if (m_stopped) break;

        WaitForDebugEvent(&m_debug_event, INFINITE);
        m_events_count++;

        auto continue_status =
            m_handler->HandleDebugEvent(&m_debug_event, this);

        ContinueDebugEvent(m_debug_event.dwProcessId,
                m_debug_event.dwThreadId,
                continue_status);

    }
}
