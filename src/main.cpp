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

    auto ins = instrumenter();
    std::vector<const char*> cov_mods;
    GetOptionAll("--cov", argc, argv, cov_mods);
    if (!cov_mods.size()) {
        SAY_ERROR("Specify at least one --cov parameter.\n");
        exit(-1);
        return -1;
    }
    for (auto &mod: cov_mods) {
        ins.add_module(mod);
    }
    auto is_inst_debug = GetBinaryOption("--inst_debug", argc, argv, false);
    if (is_inst_debug) {
        SAY_INFO("inst_debug = true\n");
        ins.set_debug();
    }
    auto is_inst_int3 = GetBinaryOption("--inst_int3", argc, argv, true);
    if (is_inst_int3) {
        SAY_INFO("inst_int3 = true\n");
        ins.set_int3_inst();
    }
    auto is_fix_dd_refs = GetBinaryOption("--fix_dd_refs", argc, argv, true);
    if (is_fix_dd_refs) {
        SAY_INFO("fix_dd_refs = true\n");
        ins.set_fix_dd_refs();
    }

    auto cmd = GetOption("--cmd", argc, argv);
    if (!cmd) {
        SAY_ERROR("Specify --cmd parameter.\n");
        exit(-1);
        return -1;
    }
    auto dbg = debugger(cmd, 
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);
    
    dbg.register_handler(&ins);
    dbg.run(-1);

    return -1;
}
