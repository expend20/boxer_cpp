#include "inproc_harness.h"
#include "say.h"

inprocess_dll_harness::inprocess_dll_harness(
        size_t lib, 
        const char* proc_name,
        const char* init_name,
        int argc,
        const char** argv) {

    m_fuzz_proc = (t_fuzz_proc)GetProcAddress((HMODULE)lib, proc_name);
    if (!m_fuzz_proc) 
        SAY_FATAL("Can't find proc %s in %p mod\n", proc_name, lib);

    if (init_name) {
        auto init = (t_init_func)GetProcAddress((HMODULE)lib, init_name);
        if (!init) SAY_FATAL("Can't find init func: %s\n", init_name);
        init(argc, argv);

        SAY_INFO("Sleeping to make harness happy...\n");
        Sleep(3*1000); // FIXME: this is placed for haness which ...
        SAY_INFO("Sleeping done\n");
    }
}

void inprocess_dll_harness::call_fuzz_proc(const char* data, size_t len) {
    ASSERT(m_fuzz_proc);
    m_fuzz_proc(data, len);
}

