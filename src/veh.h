#ifndef VEH_H

#include <set>
#include <windows.h>

struct iveh_handler {
    virtual DWORD handle_veh(_EXCEPTION_POINTERS* ExceptionInfo) = 0;
};

class veh_installer {
    public:
        veh_installer();
        void register_handler(iveh_handler* handler) { 
            EnterCriticalSection(&m_crit_sect);
            m_user_handlers.insert(handler);
            LeaveCriticalSection(&m_crit_sect);
        };
        void unregister_handler(iveh_handler* handler) { 
            EnterCriticalSection(&m_crit_sect);
            m_user_handlers.erase(handler);
            LeaveCriticalSection(&m_crit_sect);
        };
        void unregister_all() {
            m_user_handlers.clear();
        }

    private:
        static veh_installer* m_inst;
        static CRITICAL_SECTION m_crit_sect;
        static LONG WINAPI static_handler( _EXCEPTION_POINTERS* ex_info);

        PVOID m_veh_handler = 0;
        std::set<iveh_handler*> m_user_handlers;
};

#endif // VEH_H


