#include "say.h"
#include "common.h"
#include "tools.h"
#include "args.h"

#include <strsafe.h>
#include <psapi.h>

#include "instrumenter.h"

int main(int argc, const char** argv)
{
    
    init_logs(argc, argv);

    if (argc == 1 || GetBinaryOption("-h", argc, argv, false) ||
            GetBinaryOption("--help", argc, argv, false)) {
        SAY_INFO_RAW("Usage:\n\t%s --cov <mod> --cmd <cmd line>\n", argv[0]);
        SAY_INFO_RAW("Instrumentation options:\n\t"
                "--inst_bbs_file --inst_bbs_all --inst_int3_blind --fix_dd_refs"
                " --call_to_jump --skip_small_bb --stop_at {num}\n");
        SAY_INFO_RAW("Debug options:\n\t"
                "--disasm --show_flow --inst_debug --trans_debug --single_step"
                "\n");
        return -1;
    }

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

    auto is_inst_bbs_path = GetOption("--inst_bbs_file", argc, argv);
    if (is_inst_bbs_path) {
        SAY_INFO("inst_bbs_file = %s\n", is_inst_bbs_path);
        ins.set_bbs_inst();
        ins.set_bbs_path(is_inst_bbs_path);
    }
    auto is_inst_int3_blind = GetBinaryOption("--inst_int3_blind", 
            argc, argv, false);
    if (is_inst_int3_blind) {
        SAY_INFO("inst_int3_blind = true\n");
        ins.set_int3_inst_blind();
    }
    auto is_inst_bbs_all = GetBinaryOption("--inst_bbs_all", 
            argc, argv, true);
    if (is_inst_bbs_all) {
        SAY_INFO("inst_bbs_all = true\n");
        ins.set_bbs_inst_all();
    }
    auto is_call_to_jump = GetBinaryOption("--call_to_jump", 
            argc, argv, true);
    if (is_call_to_jump) {
        SAY_INFO("call_to_jump = true\n");
        ins.set_call_to_jump();
    }
    auto is_skip_small_bb = GetBinaryOption("--skip_small_bb", 
            argc, argv, false);
    if (is_skip_small_bb) {
        SAY_INFO("skip_small_bb = true\n");
        ins.set_skip_small_bb();
    }

    auto is_fix_dd_refs = GetBinaryOption("--fix_dd_refs", argc, argv, true);
    if (is_fix_dd_refs) {
        SAY_INFO("fix_dd_refs = true\n");
        ins.set_fix_dd_refs();
    }

    auto is_inst_debug = GetBinaryOption("--inst_debug", argc, argv, false);
    if (is_inst_debug) {
        SAY_INFO("inst_debug = true\n");
        ins.set_debug();
    }
    auto is_trans_debug = GetBinaryOption("--trans_debug", argc, argv, false);
    if (is_trans_debug) {
        SAY_INFO("is_trans_debug = true\n");
        ins.set_trans_debug();
    }
    auto is_disasm = GetBinaryOption("--disasm", argc, argv, false);
    if (is_disasm) {
        SAY_INFO("disasm = true\n");
        ins.set_trans_disasm();
    }
    auto is_single_step = GetBinaryOption(
            "--single_step", argc, argv, false);
    if (is_single_step) {
        SAY_INFO("single_step = true\n");
        ins.set_trans_single_step();
    }
    auto is_show_flow = GetBinaryOption(
            "--show_flow", argc, argv, false);
    if (is_show_flow) {
        SAY_INFO("show_flow = true\n");
        ins.set_show_flow();
    }

    auto stop_at = GetOption("--stop_at", argc, argv);
    if (stop_at) {
        uint32_t cycles = atoi(stop_at);
        SAY_ERROR("stop_at = %d\n", cycles);
        ins.set_stop_at(cycles);
    }

    auto cmd = GetOption("--cmd", argc, argv);
    if (!cmd) {
        SAY_ERROR("Specify --cmd parameter.\n");
        return -1;
    }

    auto dbg = debugger(cmd, 
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);
    
    dbg.register_handler(&ins);
    dbg.run(-1);
    ins.uninstrument_all();

    return -1;
}
