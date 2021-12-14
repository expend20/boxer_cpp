#include "veh.h"
#include "say.h"

veh_installer* veh_installer::m_inst = 0;
CRITICAL_SECTION veh_installer::m_crit_sect;

LONG WINAPI veh_installer::static_handler(_EXCEPTION_POINTERS* ex_info) {

    EnterCriticalSection(&m_crit_sect);

    LONG res = EXCEPTION_CONTINUE_SEARCH;
    if (m_inst && m_inst->m_user_handler){

        res = m_inst->m_user_handler->handle_veh(ex_info);

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

