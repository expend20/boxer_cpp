#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <stdint.h>
#include <windows.h>

class Debugger;

struct IDebugHandler {
    virtual ~IDebugHandler() = default;
    virtual DWORD HandleDebugEvent(DEBUG_EVENT* dbg_event,
            Debugger* debuger) = 0;
};

class Debugger {
    public:
        Debugger(const char* cmd_line, uint32_t flags);

        ~Debugger();

        void Run(size_t steps);

        void RegisterHandler(IDebugHandler* handler) { m_handler = handler; };
        const PROCESS_INFORMATION* GetProcInfo() { return &m_pi; };
        size_t GetEventsCount() { return m_events_count; };
        void Stop() { m_stopped = true; };

    private:
        PROCESS_INFORMATION m_pi = {0};
        size_t m_events_count = 0;
        DEBUG_EVENT m_debug_event = {0};
        IDebugHandler* m_handler = 0;
        bool m_stopped = false;

};

#endif
