#include "say.h"
#include "common.h"
#include "tools.h"
#include "args.h"

#include <strsafe.h>
#include <psapi.h>

#include "instrumenter.h"
#include "mutator.h"

typedef void (*t_fuzz_proc)(const char* data, size_t len);
typedef void (*t_init_func)();

class in_process_dll_harness {

    private:
        HMODULE lib = 0;
        t_fuzz_proc fuzz_proc = 0;

    public:
        in_process_dll_harness(const char* lib_path, 
                const char* proc_name,
                const char* init_name) {

            lib = LoadLibrary(lib_path);
            if (!lib) 
                SAY_FATAL("Can't load library %s\n", lib_path);

            fuzz_proc = (t_fuzz_proc)GetProcAddress(lib, proc_name);
            if (!fuzz_proc) 
                SAY_FATAL("Can't find proc %s in %p mod\n", proc_name, lib);

            if (init_name) {
                auto init = (t_init_func)GetProcAddress(lib, init_name);
                if (!init) SAY_FATAL("Can't find init func: %s\n", init_name);
                init();
            }
        }

        void call_fuzz_proc(const char* data, size_t len) {
            ASSERT(fuzz_proc);
            fuzz_proc(data, len);
        }

        size_t get_module() { return (size_t)lib; }

        ~in_process_dll_harness() {
            if (lib) FreeLibrary(lib);
        }
};

struct fuzzer_stats {
    ULONGLONG execs = 0;
};

class in_process_fuzzer {
    public: 
        in_process_fuzzer(
                in_process_dll_harness* harness, 
                instrumenter* inst) : 
            m_harness_inproc(harness), 
            m_inst(inst)
        {
            m_mutator = mutator();
            // init mutator
            {
                std::vector<uint8_t> d;
                d.resize(256);
                for (uint32_t i = 0; i < d.size(); i++) {
                    d[i] = rand() % 256;
                }
                m_mutator.add_sample_to_corpus(d);
            }

            // TODO: init coverage tool
        }
        void run();

    private:
        void print_stats(bool force);

    private:
        in_process_dll_harness* m_harness_inproc = 0;
        instrumenter* m_inst = 0;

        mutator m_mutator;
        uint32_t m_stats_sec_timeout = 3;

        fuzzer_stats m_stats;
};

void in_process_fuzzer::print_stats(bool force) 
{
    static ULONGLONG prevTicks = GetTickCount64();
    static ULONGLONG printStatsCount = 1;

    ULONGLONG newTicks = GetTickCount64();
    if (newTicks - prevTicks > 1000 * m_stats_sec_timeout || force) {
        static ULONGLONG prevExecs = 1;

        ULONGLONG newExecs = m_stats.execs - prevExecs;
        auto fcps = (double)newExecs / m_stats_sec_timeout;
        SAY_INFO("%8.2f overall fcps, %8.2f current fcps\n"
                "%10d total execs, %10d new execs\n",
                (double)m_stats.execs / (printStatsCount * m_stats_sec_timeout),
                fcps,
                m_stats.execs, newExecs 
                );
        m_inst->print_stats();

        printStatsCount++;
        prevTicks = newTicks;
        prevExecs = m_stats.execs;
    }
}

void in_process_fuzzer::run() 
{
    auto new_sample = 
        helper::readFile("z:\\in\\in_cr_new_samples\\w10-valid\\nikon_d1h.nef");
    do { 
        if (m_stats.execs % 10 == 0) {
            print_stats(false);
        }

        //
        // clear coverage
        //
        m_inst->clear_cov();
        m_inst->clear_cmpcov();

        //
        // get mutation
        //
        //auto new_sample = m_mutator.get_next_mutation();

        //
        // run code
        //
        //SAY_INFO("sample: %p %x\n", &new_sample[0], new_sample.size());
        m_stats.execs++;
        m_harness_inproc->call_fuzz_proc((const char*)&new_sample[0], 
                new_sample.size());

        // is crashed? how to restart?

        //
        // get coverage
        // 
        //{ // check cov
        //    //SAY_INFO("cov:\n");
        //    uint32_t cov_size = 0;
        //    uint8_t* cov = m_inst->get_cov(&cov_size);
        //    //SAY_INFO("cov size %d\n", cov_size);
        //    uint32_t cov_hit = 0;
        //    for (uint32_t i = 0; i < cov_size; i++) {
        //        if (cov[i]) {
        //            cov_hit++;
        //            //SAY_INFO("%x: %x ", i, cov[i]);
        //        }
        //    }
        //    //SAY_INFO("\n%x bbs hit\n", cov_hit);
        //}

        //{ // check cmpcov
        //    SAY_INFO("cmpcov:\n");
        //    uint32_t cmpcov_size = 0;
        //    uint8_t* cmpcov = m_inst->get_cmpcov(&cmpcov_size);
        //    SAY_INFO("cmpcov size %d\n", cmpcov_size);
        //    uint32_t cmpcov_hit = 0;
        //    for (uint32_t i = 0; i < cmpcov_size; i++) {
        //        if (cmpcov[i]) {
        //            cmpcov_hit++;
        //            SAY_INFO("%x: %x ", i, cmpcov[i]);
        //        }
        //    }
        //    SAY_INFO("\n%x bbs hit\n", cmpcov_hit);
        //}

        // if new coverage, stabilize it

        // add to corpus

    }while(1);
}

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

    auto is_cmpcov = GetBinaryOption("--cmpcov", 
            argc, argv, true);
    if (is_cmpcov) {
        SAY_INFO("cmpcov = true\n");
        ins.set_trans_cmpcov();
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
    auto covbuf_size = GetOption("--covbuf_size", argc, argv);
    if (covbuf_size) {
        uint32_t v = atoi(covbuf_size) * 1024;
        SAY_ERROR("covbuf_size = %d\n", v);
        ins.set_covbuf_size(v);
    }

    auto dll = GetOption("--dll", argc, argv);
    if (!dll) {
        dll = "HarnessWicLib.dll";
    }
    if (!cov_mods.size()) {
        SAY_INFO("Module to instrument: %s\n", dll);
        cov_mods.push_back(dll);
    }

    auto func = GetOption("--func", argc, argv);
    if (!func) {
        func = "fuzzIteration"; 
    }

    auto init_func = GetOption("--init_func", argc, argv);
    if (!init_func) {
        init_func = "initHeif"; 
    }

    auto vehi = veh_installer();
    vehi.register_handler(&ins);

    auto in_proc_harn = in_process_dll_harness(dll, func, init_func);
    std::vector<size_t> libs_resolved;
    for (auto &mod_name: cov_mods) {
        auto lib = (size_t)LoadLibrary(mod_name);
        if (!lib) 
            SAY_FATAL("Can't load %s\n", mod_name);
        libs_resolved.push_back(lib);
        ins.explicit_instrument_module(lib, mod_name);
    }

    auto fuzz = in_process_fuzzer(&in_proc_harn, &ins);
    fuzz.run();

    SAY_INFO("---\n");
    ins.print_stats();
    for (auto &addr: libs_resolved) {
        ins.uninstrument(addr);
        FreeLibrary((HMODULE)addr);
    }

    return -1;
}
