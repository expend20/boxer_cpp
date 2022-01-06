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
    CmpCov = 1 << 3,
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
    //{"FuzzMe1", BitCov, Crash},
    //{"FuzzMeTimeout", BitCov, Timeout},
    //{"FuzzMe2_inc", IncCov, Crash},
    //{"FuzzMe3", IncCov | StrcmpCov, Crash},
    //{"FuzzMe4", CmpCov, Crash},
    //{"FuzzMe5", BitCov, Crash},
    //{"FuzzMe6", CmpCov, Crash},
    //{"FuzzMe7", CmpCov, Crash},
    //
    //{"FuzzMeDWORD", CmpCov, Crash},
    //{"FuzzMeStack", BitCov | CmpCov, Crash},
    //{"FuzzMeOOBR", BitCov, Crash}, // works only with verifier
    //{"FuzzMeHeapCorruption", BitCov | CmpCov, Crash},
    //{"FuzzMeMyMemcmp", IncCov | CmpCov, Crash},
    //{"FuzzMePatternMatch_idx", IncCov | CmpCov, Crash},
    //
    //{"FuzzMeCmpRegImm", CmpCov, Crash},
    //{"FuzzMeCmpRegReg", CmpCov, Crash},
    //{"FuzzMeCmpMemReg", CmpCov, Crash},
    //{"FuzzMeCmpMemImm", CmpCov, Crash},
    //{"FuzzMeCmpStkReg", CmpCov, Crash},
    //{"FuzzMeCmpRelReg", CmpCov, Crash},
    //{"FuzzMeCmpRegRel", CmpCov, Crash},
    
    //{"FuzzStr0", StrcmpCov, Crash},
    //{"FuzzStr1", StrcmpCov, Crash},
    //{"FuzzStr2", StrcmpCov, Crash},
    //{"FuzzStr3", StrcmpCov, Crash},
    //{"FuzzMeBigStr", IncCov, Crash}, // grow buf
    //{"FuzzMeNotSoBigStr", IncCov, Crash}, // shrink buf
    //{"FuzzMeWithoutSymbolic", IncCov, Crash}, // it's working but takes too much time
    {"FuzzMeAvoid", CmpCov, Crash}, 
    
    //{"FuzzMeSubRegImm", CmpCov, Crash},
    
    //{"FuzzMe8", HashCov, Crash}, // takes a while, hashcov only
    //{"FuzzMeStackOverflow", BitCov, Crash}, // TODO: process stop
    //{"FuzzMeStackChkstk", BitCov | CmpCov, Crash}, // TODO: process stop
    //{"FuzzMeSubRegReg", CmpCov, Crash}, // FIXME
    //{"FuzzMeSubMemReg", CmpCov, Crash}, // FIXME
    //{"FuzzMeSubStkReg", CmpCov, Crash}, // FIXME
    //{"FuzzMeSubRelReg", CmpCov, Crash}, // FIXME
    //{"FuzzStr4", StrcmpCov, Crash}, // FIXME
    //{"FuzzStr5", StrcmpCov, Crash}, // FIXME
    //{"FuzzStr6", StrcmpCov, Crash}, // FIXME
    

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
        vehi.register_handler(&ins);

        ins.set_trans_disasm();
        ins.set_covbuf_size(512);
        ins.set_fix_dd_refs();

        if (el.opts & CmpCov) {
            ins.set_trans_cmpcov();
        }
        ins.explicit_instrument_module((size_t)lib, "AccTest.dll");

        auto inproc_harn = inprocess_dll_harness((size_t)lib, el.name, 0, 0, 0);
        auto inproc_fuzz = inprocess_fuzzer(&inproc_harn, &ins);

        vehi.register_handler(&inproc_fuzz);

        inproc_fuzz.set_zero_corp_sample_size(32);
        inproc_fuzz.set_timeout(1000);
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

        ins.uninstrument_all();
        vehi.unregister_handler(&inproc_fuzz);
        vehi.unregister_handler(&ins);
    }

    FreeLibrary(lib);
}
