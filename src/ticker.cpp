#include "ticker.h"
#include "say.h"

bool time_ticker::tick() {

    if (!m_interval) SAY_FATAL("Can't use time tick() without an interval\n");

    if (GetTickCount64() - m_time >= m_interval) {
        reset();
        return true;
    }
    else {
        return false;
    }
}

bool num_ticker::tick() {

    if (!m_interval) SAY_FATAL("Can't use num tick() without an interval\n");

    m_tick++;
    if (m_tick >= m_interval) {
        reset();
        return true;
    }
    else {
        return false;
    }
}
