#include "say.h"
#include "common.h"
#include "tools.h"
#include "args.h"

#include <strsafe.h>
#include <psapi.h>

#include "instrumenter.h"

typedef void (*t_fuzz_proc)(const char* data, size_t len);

class test_acc_test {

    private:
        HMODULE lib = 0;
        t_fuzz_proc fuzz_proc = 0;

    public:
        test_acc_test(const char* lib_path, const char* proc_name) {

            lib = LoadLibrary(lib_path);
            if (!lib) 
                SAY_FATAL("Can't load library %s\n", lib_path);

            fuzz_proc = (t_fuzz_proc)GetProcAddress(lib, proc_name);
            if (!fuzz_proc) 
                SAY_FATAL("Can't find proc %s in %p mod\n", proc_name, lib);

        }

        void call_fuzz_proc(const char* data, size_t len) {
            ASSERT(fuzz_proc);
            fuzz_proc(data, len);
        }

        size_t get_module() { return (size_t)lib; }

        ~test_acc_test() {
            if (lib) FreeLibrary(lib);
        }
};

void load_lib_and_call_proc()
{
    auto lib = LoadLibrary("AccTest.dll");
}

int main(int argc, const char** argv)
{
    InitLogs(argc, argv);

    auto ins = instrumenter();
    std::vector<const char*> cov_mods;
    GetOptionAll("--cov", argc, argv, cov_mods);

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

    auto dll = GetOption("--dll", argc, argv);
    if (!dll) {
        dll = "AccTest.dll";
    }
    if (!cov_mods.size()) {
        SAY_INFO("Module to instrument: %s\n", dll);
        cov_mods.push_back(dll);
    }

    auto func = GetOption("--func", argc, argv);
    if (!func) {
        func = "FuzzMe1"; 
    }

    auto vehi = veh_installer();
    vehi.register_handler(&ins);

    auto tester = test_acc_test(dll, func);
    std::vector<size_t> libs_resolved;
    for (auto &mod_name: cov_mods) {
        auto lib = (size_t)LoadLibrary(mod_name);
        if (!lib) 
            SAY_FATAL("Can't load %s\n", mod_name);
        libs_resolved.push_back(lib);
        ins.explicit_instrument_module(lib, mod_name);
    }

    tester.call_fuzz_proc("_337133_", 8);

    ins.print_stats();
    for (auto &addr: libs_resolved) {
        ins.uninstrument(addr);
        FreeLibrary((HMODULE)addr);
    }

    return -1;
}
