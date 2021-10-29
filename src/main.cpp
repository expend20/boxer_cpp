#include "Say.h"
#include "common.h"
#include "tools.h"

#include <strsafe.h>
#include <psapi.h>

#include "instrumenter.h"


int main(int argc, const char** argv) {
    
    InitLogs(argc, argv);
    SAY_INFO("Hello %s", "world\n");


    auto dbg = debugger("notepad.exe", 
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);

    auto ins = instrumenter();
    ins.add_module("notepad.exe");
    
    dbg.register_handler(&ins);
    dbg.run(-1);

    return -1;
}
