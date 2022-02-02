#ifndef TICKER_H

#include <windows.h>

class iticker {
    // this function is called on every iteration and returns true only if
    // the state is changed
    virtual void set_interval(ULONGLONG i) = 0;
    virtual bool tick() = 0;
    virtual void reset() = 0;
};

class time_ticker: public iticker {

    public:
        time_ticker() { reset(); }

        void set_interval(ULONGLONG i ) override { m_interval = i; };
        bool tick() override;
        void reset() override { m_time = GetTickCount64(); };

    private:
        ULONGLONG m_time = 0;
        ULONGLONG m_interval = 0;

};

class num_ticker: public iticker {

    public:
        num_ticker() { reset(); }

        void set_interval(ULONGLONG i ) override { m_interval = i; };
        bool tick() override;
        void reset() override { m_tick = 0; };

    private:
        ULONGLONG m_tick = 0;
        ULONGLONG m_interval = 0;

};

#endif // TICKER_H
