#include "say.h"
#include "common.h"
#include "tools.h"
#include "args.h"

#include <strsafe.h>
#include <psapi.h>

#include "inproc_fuzzer.h"

int main(int argc, const char** argv)
{
    __debugbreak();
    init_logs(argc, argv);

    auto ins = instrumenter();
    std::vector<const char*> cov_mods;
    GetOptionAll("--cov", argc, argv, cov_mods);

    auto is_inst_bbs_path = GetOption("--inst_bbs_file", argc, argv);
    if (is_inst_bbs_path) {
        ins.set_bbs_inst();
        ins.set_bbs_path(is_inst_bbs_path);
    }
    SAY_INFO("inst_bbs_file = %s\n", is_inst_bbs_path);

    auto is_inst_bbs_all = GetBinaryOption("--inst_bbs_all", 
            argc, argv, true);
    if (is_inst_bbs_all) {
        ins.set_bbs_inst_all();
    }
    SAY_INFO("inst_bbs_all = %d\n", is_inst_bbs_all);

    auto is_call_to_jump = GetBinaryOption("--call_to_jump", 
            argc, argv, false);
    if (is_call_to_jump) {
        ins.set_call_to_jump();
    }
    SAY_INFO("call_to_jump = %d\n", is_call_to_jump);

    auto is_skip_small_bb = GetBinaryOption("--skip_small_bb", 
            argc, argv, false);
    if (is_skip_small_bb) {
        ins.set_skip_small_bb();
    }
    SAY_INFO("skip_small_bb = %d\n", is_skip_small_bb);

    auto is_fix_dd_refs = GetBinaryOption("--fix_dd_refs", argc, argv, true);
    if (is_fix_dd_refs) {
        ins.set_fix_dd_refs();
    }
    SAY_INFO("fix_dd_refs = %d\n", is_fix_dd_refs);

    auto is_deterministic = GetBinaryOption("--deterministic", argc, argv,
            false);
    if (is_deterministic)
        srand(__rdtsc());
    SAY_INFO("dterministric = %d\n", is_deterministic);

    auto is_hashcov = GetBinaryOption("--hashcov", argc, argv, false);
    SAY_INFO("hashcov = %d\n", is_hashcov);

    auto is_inccov = GetBinaryOption("--inccov", argc, argv, true);
    SAY_INFO("inccov = %d\n", is_inccov);

    auto is_bitcov = GetBinaryOption("--bitcov", argc, argv, true);
    SAY_INFO("bitcov = %d\n", is_bitcov);

    auto is_cmpcov = GetBinaryOption("--cmpcov", argc, argv, true);
    if (is_cmpcov) {
        ins.set_trans_cmpcov();
    }
    SAY_INFO("cmpcov = %d\n", is_cmpcov);

    auto is_strcmpcov = GetBinaryOption( "--strcmp", argc, argv, false);
    SAY_INFO("strcmpcov = %d\n", is_strcmpcov);

    auto is_leaks = GetBinaryOption( "--leaks", argc, argv, true);
    SAY_INFO("leaks = %d\n", is_leaks);

    auto is_inst_debug = GetBinaryOption("--inst_debug", argc, argv, false);
    if (is_inst_debug) {
        ins.set_debug();
    }
    SAY_INFO("inst_debug = %d\n", is_inst_debug);

    auto is_trans_debug = GetBinaryOption("--trans_debug", argc, argv, false);
    if (is_trans_debug) {
        ins.set_trans_debug();
    }
    SAY_INFO("trans_debug = %d\n", is_trans_debug);

    auto is_disasm = GetBinaryOption("--disasm", argc, argv, false);
    if (is_disasm) {
        ins.set_trans_disasm();
    }
    SAY_INFO("disasm = %d\n", is_disasm);

    auto is_single_step = GetBinaryOption(
            "--single_step", argc, argv, false);
    if (is_single_step) {
        ins.set_trans_single_step();
    }
    SAY_INFO("single_step = %d\n", is_single_step);

    auto is_show_flow = GetBinaryOption(
            "--show_flow", argc, argv, false);
    if (is_show_flow) {
        ins.set_show_flow();
    }
    SAY_INFO("show_flow = %d\n", is_show_flow);

    auto is_cmin = GetBinaryOption( "--cmin", argc, argv, false);
    SAY_INFO("cmin = %d\n", is_cmin);

    auto stop_at = GetOption("--stop_at", argc, argv);
    if (stop_at) {
        uint32_t cycles = atoi(stop_at);
        SAY_INFO("stop_at = %d\n", cycles);
        ins.set_stop_at(cycles);
    }

    auto covbuf_size = GetOption("--covbuf_size", argc, argv);
    uint32_t covbuf_size_v = 64 * 1024;
    if (covbuf_size) {
        covbuf_size_v = atoi(covbuf_size);
    }
    SAY_INFO("covbuf_size = %d\n", covbuf_size_v);
    ins.set_covbuf_size(covbuf_size_v);

    auto timeout = GetOption("--timeout", argc, argv);
    uint32_t timeout_v = 10000;
    if (timeout) {
        timeout_v = atoi(timeout);
    }
    SAY_INFO("timeout_v = %d\n", timeout_v);

    uint32_t zero_corp_sample_size_val = 256;
    auto zero_corp_sample_size = GetOption("--zero_corp_sample_size", 
            argc, argv);
    if (zero_corp_sample_size) {
        zero_corp_sample_size_val = atoi(zero_corp_sample_size);
    }
    SAY_INFO("zero_corp_sample_size = %d\n", zero_corp_sample_size_val);

    uint32_t mutator_density_val = 256;
    auto mutator_density = GetOption("--mutator_density", argc, argv);
    if (mutator_density) {
        mutator_density_val = atoi(mutator_density);
    }
    SAY_INFO("mutator_desity = %d\n", mutator_density_val);

    auto dll = GetOption("--dll", argc, argv);
    if (!dll) {
        dll = "HarnessWicLib.dll";
    }
    SAY_INFO("Module to instrument: %s\n", dll);

    auto func = GetOption("--func", argc, argv);
    if (!func) {
        func = "fuzzIteration"; 
    }
    SAY_INFO("func = %s\n", func);

    auto init_func = GetOption("--init_func", argc, argv);
    SAY_INFO("init_func = %s\n", init_func);

    auto input_dir = GetOption("--in", argc, argv);
    if (!input_dir) {
        input_dir = "in"; 
    }

    auto output_dir = GetOption("--out", argc, argv);
    if (!output_dir) {
        static std::string out = "out_auto";
        if (is_cmin) {
            out += "_cmin";
        }
        if (init_func) {
            out += "_"; 
            out += init_func;
        }
        out += "_";
        out += cov_mods.size() ? cov_mods[0] : "nocov";
        output_dir = out.c_str();
    }
    SAY_INFO("Output directory = %s\n", output_dir);

    auto crash_dir = GetOption("--crash", argc, argv);
    if (!crash_dir) {
        static std::string s = output_dir;
        s += "_crash";
        crash_dir = s.c_str();
    }
    SAY_INFO("Crash directory = %s\n", crash_dir);

    auto timeout_dir = GetOption("--timeout_dir", argc, argv);
    if (!timeout_dir) {
        static std::string s = output_dir;
        s += "_timeout";
        timeout_dir = s.c_str();
    }
    SAY_INFO("Timeout directory = %s\n", timeout_dir);

    auto is_save_samples = GetBinaryOption(
            "--save_samples", argc, argv, true);
    SAY_INFO("save_samples = %d\n", is_show_flow);

    auto vehi = veh_installer();
    vehi.register_handler(&ins);

    auto lib_harness = LoadLibrary(dll);
    DisableThreadLibraryCalls(lib_harness);
    if (!lib_harness)
        SAY_FATAL("Can't load dll: %s, %s\n", dll, 
                helper::getLastErrorAsString().c_str());

    auto inproc_harn = inprocess_dll_harness((size_t)lib_harness, func, 
            init_func, argc, argv);
    std::vector<size_t> libs_resolved;
    for (auto &mod_name: cov_mods) {
        auto lib = (size_t)LoadLibrary(mod_name);
        if (!lib) 
            SAY_FATAL("Can't load %s\n", mod_name);
        libs_resolved.push_back(lib);
        ins.explicit_instrument_module(lib, mod_name);
    }
    if (is_strcmpcov) {
        ins.install_strcmpcov();
    }
    if (is_leaks) {
        ins.install_leaks();
    }

    auto inproc_fuzz = inprocess_fuzzer(&inproc_harn, &ins);
    vehi.register_handler(&inproc_fuzz);
    inproc_fuzz.set_argc_argv(argc, argv);
    if (input_dir)
        inproc_fuzz.set_input(input_dir);
    if (output_dir)
        inproc_fuzz.set_output(output_dir);
    if (crash_dir)
        inproc_fuzz.set_crash_dir(crash_dir);
    if (is_cmin)
        inproc_fuzz.set_cmin_mode();
    if (zero_corp_sample_size_val)
        inproc_fuzz.set_zero_corp_sample_size(zero_corp_sample_size_val);
    if (is_inccov)
        inproc_fuzz.set_inccov();
    if (is_bitcov)
        inproc_fuzz.set_bitcov();
    if (is_hashcov)
        inproc_fuzz.set_hashcov();
    if (timeout_v) {
        inproc_fuzz.set_timeout(timeout_v);
    }
    inproc_fuzz.set_save_samples(is_save_samples);
    inproc_fuzz.run();

    ins.print_stats();
    for (auto &addr: libs_resolved) {
        ins.uninstrument(addr);
        FreeLibrary((HMODULE)addr);
    }
    FreeLibrary(lib_harness);

    return -1;
}
