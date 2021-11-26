#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <stdint.h>
#include <windows.h>

class debugger;

struct idebug_handler {
    virtual DWORD handle_debug_event(DEBUG_EVENT* dbg_event,
            debugger* debuger) = 0;
};

class debugger {
    public:
        debugger(const char* cmd_line, uint32_t flags);

        ~debugger();

        void run(size_t steps);

        void register_handler(idebug_handler* handler) { m_handler = handler; };
        PROCESS_INFORMATION* get_proc_info() { return &m_pi; };
        size_t get_events_count() { return m_events_count; };
        void stop() { m_stopped = true; };

    private:
        PROCESS_INFORMATION m_pi = {0};
        size_t m_events_count = 0;
        DEBUG_EVENT m_debug_event = {0};
        idebug_handler* m_handler = 0;
        bool m_stopped = false;

};

#endif
