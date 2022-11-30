#include "say.h"
#include "common.h"
#include "args.h"
#include "inproc_fuzzer.h"

#include <map>

enum AccTestCaseOption {
    BitCov = 1 << 0,
    IncCov = 1 << 1,
    HashCov = 1 << 2,
    StrcmpCov = 1 << 3,
    CmpCov = 1 << 4,
    MaxCov = 1 << 5,
};

enum AccTestCaseResult {
    Timeout = 1 << 0,
    Crash = 1 << 1,
};

typedef struct _AccTestCase {
    const char* name;
    size_t opts;
    size_t result;
    size_t meta;
} AccTestCase;

std::map<std::string, uint32_t> g_crash_counts = {
    {"FuzzMeAvoid", 2}
};

AccTestCase AccTests[] = {
    {"FuzzMe9", CmpCov, Crash},

    /*
#ifndef _WIN64
    {"FuzzMeSEH", CmpCov, Crash},
    {"FuzzMeCPPEH", CmpCov, Crash},
#endif

    {"FuzzMe1", BitCov, Crash},
    {"FuzzMeTimeout", BitCov, Timeout},
    {"FuzzMe2_inc", IncCov, Crash},
    {"FuzzMe3", IncCov | StrcmpCov, Crash},
    {"FuzzMe4", CmpCov | BitCov, Crash},
    {"FuzzMe5", BitCov, Crash},
    {"FuzzMe6", CmpCov | BitCov, Crash},
    {"FuzzMe7", CmpCov | BitCov, Crash},
    
    {"FuzzMeDWORD", CmpCov | BitCov, Crash},
    {"FuzzMeStack", CmpCov | BitCov, Crash},
    {"FuzzMeMyMemcmp", IncCov | CmpCov, Crash},
    {"FuzzMePatternMatch_idx", IncCov | CmpCov, Crash},
    
    {"FuzzMeCmpRegImm", CmpCov | BitCov, Crash},
    {"FuzzMeCmpRegReg", CmpCov | BitCov, Crash},
    {"FuzzMeCmpMemReg", CmpCov | BitCov, Crash},
    {"FuzzMeCmpMemImm", CmpCov | BitCov, Crash},
    {"FuzzMeCmpStkReg", CmpCov | BitCov, Crash},
    {"FuzzMeCmpRelReg", CmpCov | BitCov, Crash},
    {"FuzzMeCmpRegRel", CmpCov | BitCov, Crash},
    {"FuzzMeTestRegReg", CmpCov | BitCov, Crash},
    
    {"FuzzStr0", BitCov | StrcmpCov, Crash},
    {"FuzzStr1", BitCov | StrcmpCov, Crash},
    {"FuzzStr2", BitCov | StrcmpCov, Crash},
    {"FuzzStr3", BitCov | StrcmpCov, Crash},
    {"FuzzMeBigStr", IncCov, Crash}, // grow buf
    {"FuzzMeNotSoBigStr", IncCov, Crash}, // shrink buf
    {"FuzzMeAvoid", CmpCov | BitCov, Crash}, 
    
    {"FuzzMeSubRegImm", CmpCov | BitCov, Crash},

    {"FuzzStr4", BitCov | StrcmpCov, Crash},
    {"FuzzStr5", BitCov | StrcmpCov, Crash},
    {"FuzzStr6", BitCov | StrcmpCov, Crash},
    {"FuzzStr7", BitCov | StrcmpCov, Crash},
    
    //{"FuzzMeWithoutSymbolic", IncCov, Crash}, // it's working but takes too much time
    //{"FuzzMeOOBR", BitCov, Crash}, // works only with verifier
    //{"FuzzMeHeapCorruption", BitCov | CmpCov, Crash}, // how can we restore after this?
    //{"FuzzMe8", HashCov, Crash}, // takes a while, hashcov only

    //{"FuzzMeStackOverflow", BitCov, Crash}, // TODO: process stop
    //{"FuzzMeStackChkstk", BitCov | CmpCov, Crash}, // TODO: process stop
    //{"FuzzMeSubRegReg", CmpCov | BitCov, Crash}, // TODO: implement in acctest
    //{"FuzzMeSubMemReg", CmpCov | BitCov, Crash}, // TODO: implement in acctest 
    //{"FuzzMeSubStkReg", CmpCov | BitCov, Crash}, // TODO: implement in acctest
    //{"FuzzMeSubRelReg", CmpCov | BitCov, Crash}, // TODO: implement in acctest
    
    */

};

int main(int argc, const char** argv)
{
    init_logs(argc, argv);
    auto acctest_path = GetOption("--acctest", argc, argv);
    if (!acctest_path) {
        SAY_ERROR("Provide --acctest path\n");
        return -1;
    }
    auto save_samples = GetBinaryOption("--samples", argc, argv, false);
    auto is_disasm = GetBinaryOption("--disasm", argc, argv, false);

    if (GetBinaryOption("--break", argc, argv, false)) {
        __debugbreak();
    }

    auto is_inst_bbs_path = GetOption("--inst_bbs_file", argc, argv);
    SAY_INFO("inst_bbs_file = %s\n", is_inst_bbs_path);

    auto lib = LoadLibrary(acctest_path);
    if (!lib) {
        SAY_ERROR("Can't load library %s, %s\n", acctest_path,
                helper::getLastErrorAsString().c_str());
        return -1;
    }
    DisableThreadLibraryCalls(lib);

    auto vehi = veh_installer();

    for (auto &el: AccTests) {
        SAY_INFO("=========================================================\n");
        SAY_INFO("Running %s, opts %x, res %x\n", el.name, el.opts, el.result);
        SAY_INFO("=========================================================\n");

        auto ins = instrumenter();
        if (is_inst_bbs_path) {
            ins.set_bbs_inst();
            ins.set_bbs_inst_all();
            ins.set_bbs_path(is_inst_bbs_path);
        }
        vehi.register_handler(&ins);

        if (is_disasm)
            ins.set_trans_disasm();
        ins.set_covbuf_size(512);
        ins.set_fix_dd_refs();

        if (el.opts & CmpCov) {
            ins.set_trans_cmpcov();
        }
        ins.explicit_instrument_module((size_t)lib, "AccTest.dll");

        auto inproc_harn = inprocess_dll_harness((size_t)lib, el.name, 0, 0, 0);
        auto mo = mutator_options();
        mo.mutation_mode = regular;
        mo.mode = num_based;
        auto inproc_fuzz = inprocess_fuzzer(
                std::move(mutator(std::move(mo))),
                &inproc_harn, &ins);

        inproc_fuzz.set_zero_corp_sample_size(32);
        if (el.result & Timeout) {
            inproc_fuzz.set_timeout(500);
        }
        if (g_crash_counts.find(el.name) != g_crash_counts.end()) {
            SAY_INFO("custom crash count\n");
            inproc_fuzz.set_stop_on_unique_crash_count(
                    g_crash_counts[el.name]
                    );
        }
        else {
            inproc_fuzz.set_stop_on_unique_crash_count(1);
        }
        inproc_fuzz.set_stop_on_timeout();
        inproc_fuzz.set_output("out_acctest");
        inproc_fuzz.set_crash_dir("out_acctest_crash");
        inproc_fuzz.set_save_samples(save_samples);

        if (el.opts & BitCov) {
            inproc_fuzz.set_bitcov();
        }
        if (el.opts & IncCov) {
            inproc_fuzz.set_inccov();
        }
        if (el.opts & HashCov) {
            inproc_fuzz.set_hashcov();
        }
        if (el.opts & MaxCov) {
            inproc_fuzz.set_maxcov();
        }
        if (el.opts & StrcmpCov) {
            ins.install_strcmpcov();
        }

        inproc_fuzz.run();

        if (el.result & Crash) {
            if (!inproc_fuzz.get_stats()->crashes) {
                SAY_FATAL("Test case should crash, but it's not: %s\n", 
                        el.name);
            }
        }
        if (el.result & Timeout) {
            if (!inproc_fuzz.get_stats()->timeouts) {
                SAY_FATAL("Test case should timeout, but it's not: %s\n", 
                        el.name);
            }
        }

        if (el.opts & StrcmpCov) {
            ins.uninstall_strcmpcov();
        }

        vehi.unregister_handler(&ins);
        ins.uninstrument_all();
    }

    FreeLibrary(lib);
    SAY_INFO("All tests are ok\n");
}
