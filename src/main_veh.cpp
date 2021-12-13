#include "say.h"
#include "common.h"
#include "tools.h"
#include "args.h"

#include <strsafe.h>
#include <psapi.h>
#include <intrin.h>

#include "instrumenter.h"
#include "mutator.h"
#include "cov_tool.h"

typedef void (*t_fuzz_proc)(const char* data, size_t len);
typedef void (*t_init_func)();

const char** g_argv = 0;
int g_argc = 0;


void respawn_process(int argc, const char** argv) {

    /*
     * Restart process to avoid memory leaks
     */


    auto new_opts = helper::skip_options(argc, argv, "--threads", true);

    auto cmd = ArgvToCmd(new_opts.size(), &new_opts[0]);
    SAY_INFO("Respawning new process: %s", cmd);
    auto newProc = helper::spawn(cmd, CREATE_NEW_CONSOLE);
    exit(0);
}

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
    ULONGLONG stable_cov = 0;
    ULONGLONG unstable_cov = 0;
    ULONGLONG cmpcov_bits = 0;
    ULONGLONG mutator_samples = 0;
};

class in_process_fuzzer {
    public: 
        in_process_fuzzer( in_process_dll_harness* harness, 
                instrumenter* inst);
        void run();
        void run_one_input(const uint8_t* data, uint32_t size, 
                bool save_to_disk = true);
        bool cov_check_by_hash(const uint8_t* data, uint32_t size, 
                bool* is_unstable);
        void set_input(const char* path);
        void set_output(const char* path);
        void set_cmin_mode(){ m_cmin_mode = true; };

    private:
        void print_stats(bool force);
        void process_input_corpus();
        void process_output_corpus();
        void restart_if_should();

    private:
        in_process_dll_harness* m_harness_inproc = 0;
        instrumenter* m_inst = 0;

        mutator m_mutator;
        uint32_t m_stats_sec_timeout = 3;

        fuzzer_stats m_stats;
        cov_tool m_cov_tool;
        cov_tool m_cmpcov_tool;

        const char* m_input_corpus_path = 0;
        const char* m_output_corpus_path = 0;

        bool m_cmin_mode = false;
};

void in_process_fuzzer::set_input(const char* path)
{
    ASSERT(path);
    m_input_corpus_path = path;
}

void in_process_fuzzer::set_output(const char* path)
{
    ASSERT(path);
    m_output_corpus_path = path;
}

void in_process_fuzzer::process_input_corpus()
{
    auto in_corpus = helper::files_to_vector(m_input_corpus_path);
    SAY_INFO("Processing input corpus (%d samples)...\n", in_corpus.size());
    for (auto &sample: in_corpus) {
        run_one_input(&sample[0], sample.size(), true);
    }

    if (!in_corpus.size()) {
        // no input corpus, put at least something
        std::vector<uint8_t> sample;
        sample.resize(256);
        for (uint32_t i = 0; i < sample.size(); i++) {
            sample[i] = rand() % 256;
        }
        run_one_input(&sample[0], sample.size(), true);
    }

    if (!m_mutator.get_corpus_size()) {
        SAY_FATAL("No valid input samples\n");
    }
}

void in_process_fuzzer::process_output_corpus()
{
    auto out_corpus = helper::files_to_vector(m_output_corpus_path);
    SAY_INFO("Processing output corpus (%d samples)...\n", out_corpus.size());
    for (auto &sample: out_corpus) {
        run_one_input(&sample[0], sample.size(), false);
    }
}

in_process_fuzzer::in_process_fuzzer(
        in_process_dll_harness* harness, 
        instrumenter* inst) : 
    m_harness_inproc(harness), 
    m_inst(inst)
{
    m_mutator = mutator();
    // init mutator

}

void in_process_fuzzer::restart_if_should()
{
    if (m_inst->get_stats()->cpp_exceptions > 500 * 1000) {
        respawn_process(g_argc, g_argv);
    }
}

void in_process_fuzzer::print_stats(bool force) 
{
    static ULONGLONG prevTicks = GetTickCount64();
    static ULONGLONG printStatsCount = 1;

    ULONGLONG newTicks = GetTickCount64();
    if (newTicks - prevTicks > 1000 * m_stats_sec_timeout || force) {
        static ULONGLONG prevExecs = 1;

        ULONGLONG newExecs = m_stats.execs - prevExecs;
        auto fcps = (double)newExecs / m_stats_sec_timeout;
        SAY_INFO("%8.2f fcps (%8.2f avg) %10d samples\n"
                "%10d total execs, %10d new execs\n"
                "%10d stable cov, %10d unstable cov, %10d cmpcov bits\n",
                fcps,
                (double)m_stats.execs / (printStatsCount * m_stats_sec_timeout),
                m_stats.mutator_samples,
                m_stats.execs, newExecs,
                m_stats.stable_cov, m_stats.unstable_cov, m_stats.cmpcov_bits
                );
        m_inst->print_stats();

        printStatsCount++;
        prevTicks = newTicks;
        prevExecs = m_stats.execs;
    }
}

bool in_process_fuzzer::cov_check_by_hash(const uint8_t* data, uint32_t size,
        bool* is_unstable) 
{
    bool res = false;
    std::set<XXH128_hash_t> hashes;
    if (is_unstable) *is_unstable = false;

    static size_t cached_ret = 0;
    static uint32_t store_mark = 0;
    static uint32_t continue_mark = 0;

    uint32_t i = 0;
    for (; i < 3; i++) {
        // clear coverage
        m_inst->clear_cov();

        // WANRING: don't place any new code until restore mark, otherwise
        // adjust offsets in the handle.
        // We need to capture the current context if we need to force
        // continuation of the thread (e.g. timeout or exception)
        if (cached_ret != (size_t)_AddressOfReturnAddress()) {
            cached_ret = (size_t)_AddressOfReturnAddress();
            __debugbreak();
            store_mark = MARKER_STORE_CONTEXT;
        }
        // run the sample
        m_harness_inproc->call_fuzz_proc((const char*)data, size);
        continue_mark = MARKER_RESTORE_CONTINUE;

        uint32_t cov_sz = 0;
        auto cov = m_inst->get_cov(&cov_sz);
        ASSERT(cov && cov_sz);

        auto h = cov_tool::get_cov_hash(cov, cov_sz);
        if (!hashes.size() && !m_cov_tool.is_new_cov_hash(h, false)) {
            // first iteration without new cov
            break;
        }

        if (hashes.size() && hashes.find(h) != hashes.end()) {
            // we found one stable coverage, check it again, with state
            // modification
            if (!m_cov_tool.is_new_cov_hash(h)) {
                // oops, stable cov hash is already processed
                break;
            }
            // we've got new stable hash
            m_cov_tool.is_new_cov_hash(h);
            res = true;
            break;
        }
        hashes.insert(h);
    }
    if (res) {
        m_stats.stable_cov++;
    } else {
        if (i == 3) {
            m_stats.unstable_cov++;
            // add all unstable hashes to the cov_tool's internal state
            for (auto &h : hashes) {
                m_cov_tool.is_new_cov_hash(h);
            }
            if (is_unstable) *is_unstable = true;
        }
    }

    return res;
}

void in_process_fuzzer::run_one_input(const uint8_t* data, uint32_t size,
        bool save_to_disk) 
{
    ASSERT(data);
    ASSERT(size);
    m_stats.execs++;

    bool is_unstable = false;
    bool should_add_to_corpus = false;
    if (cov_check_by_hash(data, size, &is_unstable)) {

        uint32_t cov_sz = 0;
        uint8_t* cov = 0;
        cov = m_inst->get_cov(&cov_sz);
        if (m_cov_tool.is_new_cov_bits(cov, cov_sz)) 
            should_add_to_corpus = true;
    }

    if (is_unstable) return;

    uint32_t cmpcov_sz = 0;
    uint8_t* cmpcov = 0;
    cmpcov = m_inst->get_cmpcov(&cmpcov_sz);

    // we call this comparison in any case, because we want to have it updated
    bool is_cmpcov_bits = m_cmpcov_tool.is_new_cov_bits(cmpcov, cmpcov_sz);
    if (is_cmpcov_bits) {
        m_stats.cmpcov_bits++;
        should_add_to_corpus = true;
    }

    if (should_add_to_corpus) {
        // add to corpus, we rely here on the fact that current coverage is
        // stable
        m_mutator.add_sample_to_corpus(data, size);
        m_stats.mutator_samples++;

        if (save_to_disk) {
            // save to disk
            auto hash = cov_tool::get_cov_hash(data, size);
            auto hash_str = helper::hex_to_str((const char*)&hash, 
                    sizeof(hash));

            std::string path = m_output_corpus_path;
            path = path + "\\" + hash_str.c_str();
            helper::writeFile(path.c_str(), (const char*)data, size, "wb");
        }
    }

}

void in_process_fuzzer::run() 
{
    process_output_corpus();
    process_input_corpus();

    if (m_cmin_mode) {
        SAY_INFO("Cmin mode, %d samples saved, exiting...\n", 
                m_stats.mutator_samples);
        return;
    }

    SAY_INFO("Running fuzzing session...\n");
    //auto new_sample = 
    //    helper::readFile("z:\\in\\in_cr_new_samples\\w10-valid\\nikon_d1h.nef");
    //auto new_sample = 
    //    helper::readFile("c:\\git\\boxer_cpp\\build\\sample1");
    do { 
        if (m_stats.execs % 10 == 0) {
            print_stats(false);
            restart_if_should();
        }

        //
        // get mutation
        //
        auto new_sample = m_mutator.get_next_mutation();

        //
        // run code
        //
        //SAY_INFO("sample: %p %x\n", &new_sample[0], new_sample.size());
        run_one_input(&new_sample[0], new_sample.size());

    }while(1);
}

int main(int argc, const char** argv)
{
    InitLogs(argc, argv);
    g_argv = argv;
    g_argc = argc;

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

    auto is_cmpcov = GetBinaryOption("--cmpcov", argc, argv, true);
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
    auto is_cmin = GetBinaryOption( "--cmin", argc, argv, false);

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
    //if (!init_func) {
    //    init_func = "initRaw"; 
    //}

    auto input_dir = GetOption("--in", argc, argv);
    if (!input_dir) {
        input_dir = "initRaw"; 
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
        out += cov_mods[0];
        output_dir = out.c_str();
    }
    SAY_INFO("Output directory = %s\n", output_dir);
    // ensure directory exists
    CreateDirectoryA(output_dir, 0);

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
    ins.set_strcmpcov();

    auto fuzz = in_process_fuzzer(&in_proc_harn, &ins);
    if (input_dir)
        fuzz.set_input(input_dir);
    if (output_dir)
        fuzz.set_output(output_dir);
    if (is_cmin)
        fuzz.set_cmin_mode();
    fuzz.run();

    ins.print_stats();
    for (auto &addr: libs_resolved) {
        ins.uninstrument(addr);
        FreeLibrary((HMODULE)addr);
    }

    return -1;
}
