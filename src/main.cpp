#include "Say.h"
#include "common.h"
#include "tools.h"
#include "args.h"

#include <strsafe.h>
#include <psapi.h>

#include "instrumenter.h"

int main(int argc, const char** argv)
{
    
    InitLogs(argc, argv);
    SAY_INFO("Hello %s", "world\n");

    std::vector<const char*> cov_mods;
    GetOptionAll("--cov", argc, argv, cov_mods);
    if (!cov_mods.size()) {
        SAY_ERROR("Specify at least one --cov parameter.\n");
        exit(-1);
        return -1;
    }

    auto cmd = GetOption("--cmd", argc, argv);
    if (!cmd) {
        SAY_ERROR("Specify --cmd parameter.\n");
        exit(-1);
        return -1;
    }

    auto dbg = debugger(cmd, 
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);

    auto ins = instrumenter();
    for (auto &mod: cov_mods) {
        ins.add_module(mod);
    }
    
    dbg.register_handler(&ins);
    dbg.run(-1);

    return -1;
}
