#ifndef _INPROC_HARNESS_
#define _INPROC_HARNESS_

#include <windows.h>

typedef void (*t_fuzz_proc)(const char* data, size_t len);
typedef void (*t_init_func)(int argc, const char** argv);

class inprocess_dll_harness {

    private:
        HMODULE m_lib = 0;
        t_fuzz_proc m_fuzz_proc = 0;

    public:
        inprocess_dll_harness(size_t lib, 
                const char* proc_name,
                const char* init_name,
                int argc,
                const char** argv);

        void call_fuzz_proc(const char* data, size_t len);

        size_t get_module() { return (size_t)m_lib; };

};
#endif // _INPROC_HARNESS_
