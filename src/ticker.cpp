#include "ticker.h"

bool time_ticker::tick() {
    if (GetTickCount64() - m_time >= m_interval) {
        reset();
        return true;
    }
    else {
        return false;
    }
}

bool num_ticker::tick() {
    m_tick++;
    if (m_tick >= m_interval) {
        reset();
        return true;
    }
    else {
        return false;
    }
}
