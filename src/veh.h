#ifndef VEH_H

#include <vector>
#include <windows.h>

struct iveh_handler {
    virtual DWORD handle_veh(_EXCEPTION_POINTERS* ExceptionInfo) = 0;
};

class veh_installer {
    public:
        veh_installer();
        void register_handler(iveh_handler* handler) { 
            m_user_handlers.push_back(handler);
        };

    private:
        static veh_installer* m_inst;
        static CRITICAL_SECTION m_crit_sect;
        static LONG WINAPI static_handler( _EXCEPTION_POINTERS* ex_info);

        PVOID m_veh_handler = 0;
        std::vector<iveh_handler*> m_user_handlers;
};

#endif // VEH_H


