#include "veh.h"
#include "say.h"

veh_installer* veh_installer::m_inst = 0;
CRITICAL_SECTION veh_installer::m_crit_sect;

LONG WINAPI veh_installer::static_handler(_EXCEPTION_POINTERS* ex_info) {

    if (!m_inst) return EXCEPTION_CONTINUE_SEARCH;

    EnterCriticalSection(&m_crit_sect);

    LONG res = EXCEPTION_CONTINUE_SEARCH;
    bool handled = false;
    for (auto &user_handler: m_inst->m_user_handlers) {
    //if (m_inst && m_inst->m_user_handler){

        res = user_handler->handle_veh(ex_info);
        if (res != EXCEPTION_CONTINUE_SEARCH) {
            handled = true;
            break;
        }
    }
    if (!handled)  {
        SAY_WARN("Intrumenter veh: Unhandled exception: %x at %p\n",
                ex_info->ExceptionRecord->ExceptionCode, 
                ex_info->ExceptionRecord->ExceptionAddress);
    }

    LeaveCriticalSection(&m_crit_sect);

    return res;
}

veh_installer::veh_installer() {

    if (m_inst) SAY_FATAL("Only one instance of veh_handler allowed\n");
    m_inst = this;
    InitializeCriticalSection(&m_crit_sect);

    m_veh_handler = AddVectoredExceptionHandler(0, static_handler);
    if (!m_veh_handler) {
        SAY_FATAL("Can't setup the VEH handler\n");
    }
    SAY_DEBUG("VEH handler set up: %p, addr %p\n", 
            m_veh_handler, &m_veh_handler);
}

