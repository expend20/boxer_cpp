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
    ULONGLONG unique_crashes = 0;
    ULONGLONG crashes = 0;
    ULONGLONG timeouts = 0;
    ULONGLONG stable_cov = 0;
    ULONGLONG unstable_cov = 0;
    ULONGLONG cmpcov_bits = 0;
    ULONGLONG new_bits = 0;
    ULONGLONG new_inc = 0;
    ULONGLONG strcmp = 0;
};

class in_process_fuzzer: public iveh_handler {
    public: 
        DWORD handle_veh(_EXCEPTION_POINTERS* ex_info) override;
        in_process_fuzzer( in_process_dll_harness* harness, 
                instrumenter* inst, uint32_t mutator_density = 0);
        void run();
        void run_one_input(const uint8_t* data, uint32_t size, 
                bool save_to_disk = true);
        bool cov_check_by_hash(const uint8_t* data, uint32_t size, 
                bool* is_unstable);
        void set_input(const char* path);
        void set_output(const char* path);
        void set_crash_dir(const char* path);
        void set_cmin_mode(){ m_cmin_mode = true; };
        void set_zero_corp_sample_size(uint32_t v) {
            m_zero_corp_sample_size = v; 
        };
        void set_inccov(){ m_is_inccov = true; };
        void set_hashcov(){ m_is_hashcov = true; };
        void set_bitcov(){ m_is_bitcov = true; };
        void set_save_samples(){ m_is_save_samples = true; };
        void set_timeout(size_t v){ m_timeout = v; };

    private:
        void print_stats(bool force);
        void process_input_corpus();
        void process_output_corpus();
        void restart_if_should();

        std::vector<std::vector<uint8_t>>
            try_to_fix_strings(uint8_t* data, uint32_t sz);

        void save_sample(const uint8_t* data, uint32_t size, 
                crash_info* crash = 0);

        static DWORD WINAPI _thread_ex_thrower(LPVOID p);

    private:
        in_process_dll_harness* m_harness_inproc = 0;
        instrumenter* m_inst = 0;

        mutator m_mutator;
        uint32_t m_stats_sec_timeout = 3;

        fuzzer_stats m_stats;
        cov_tool m_cov_tool_bits;
        cov_tool m_cov_tool_inc;
        cov_tool m_cov_tool_cmp;

        const char* m_input_corpus_path = 0;
        const char* m_output_corpus_path = 0;
        const char* m_crash_dir = 0;
        uint32_t m_zero_corp_sample_size = 12 * 1024;

        bool m_cmin_mode = false;
        bool m_is_inccov = false;
        bool m_is_hashcov = false;
        bool m_is_bitcov = false;
        bool m_is_save_samples = false;
        bool m_is_timeouted = false;

        uint32_t m_thread_id = 0;
        HANDLE m_thread_ex_thrower = 0;
        ULONGLONG m_start_ticks = 0;
        ULONGLONG m_timeout = 0;

};

DWORD in_process_fuzzer::handle_veh(_EXCEPTION_POINTERS* ex_info) 
{
    auto ex_record = ex_info->ExceptionRecord;
    auto ex_code = ex_record->ExceptionCode;

    auto res = false;
    // check for timeout on OutputDebugString messages
    if (ex_code == DBG_PRINTEXCEPTION_C) {
        if (m_start_ticks && 
                GetTickCount64() - m_start_ticks > m_timeout) {
            // timeout hit
            m_stats.timeouts++;
            m_is_timeouted = true;

            auto thread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_thread_id);
            ASSERT(thread);

            auto ctx = m_inst->get_restore_ctx();
            //SAY_INFO("Redirecting on timeout %d %p\n", m_stats.timeouts, ctx);
            ctx->ContextFlags = CONTEXT_ALL;
            auto r = SetThreadContext(thread, ctx);
            ASSERT(r);
            CloseHandle(thread);
        }
    }

    return res ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI in_process_fuzzer::_thread_ex_thrower(LPVOID p)
{
    // The purpose of this this thread is to generate exception every second
    // so we have interruptions at least each second and check hanged samples
    // in the exception handler
    while(1) {
        Sleep(50);
        OutputDebugStringA("");
    }
}

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

void in_process_fuzzer::set_crash_dir(const char* path)
{
    ASSERT(path);
    m_crash_dir = path;
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
        sample.resize(m_zero_corp_sample_size);

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
        instrumenter* inst,
        uint32_t mutator_density) : 
    m_harness_inproc(harness), 
    m_inst(inst)
{
    m_mutator = mutator();
    if (mutator_density)
        m_mutator.set_density(mutator_density);
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
        SAY_INFO("%8.2f fcps (%8.2f avg) %10d new bits %10d new inc\n"
                "%10d (%d) crashes, %10d timeouts, %10d total execs, "
                " %10d new execs\n"
                "%10d stable cov, %10d unstable cov, %10d cmpcov bits\n"
                "%10d strcmp\n",
                fcps,
                (double)m_stats.execs / (printStatsCount * m_stats_sec_timeout),
                m_stats.new_bits, m_stats.new_inc,
                m_stats.crashes, m_stats.unique_crashes, m_stats.timeouts, 
                m_stats.execs, newExecs,
                m_stats.stable_cov, m_stats.unstable_cov, m_stats.cmpcov_bits,
                m_stats.strcmp
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
    static const uint8_t* sanity_data = 0;
    static const uint32_t sanity_size = 0;
    sanity_data = data;
    sanity_size = size;

    uint32_t i = 0;
    for (; i < 3; i++) {
        // clear coverage
        m_inst->clear_cov();
        // don't need to clear cmpcov because it's only increasing bits
        
        m_start_ticks = GetTickCount64();

        // WANRING: don't place any new code until restore mark, otherwise
        // adjust offsets in the handle.
        // We need to capture the current context if we need to force
        // continuation of the thread (e.g. timeout or exception)
        if (cached_ret != (size_t)_AddressOfReturnAddress()) {
            // FIXME: how to save context without interruption on each 
            // iteration?
            cached_ret = (size_t)_AddressOfReturnAddress();
            __debugbreak();
            store_mark = MARKER_STORE_CONTEXT;
        }
        // run the sample
        m_harness_inproc->call_fuzz_proc((const char*)sanity_data, sanity_size);
        continue_mark = MARKER_RESTORE_CONTINUE;

        //if (sanity_data != data) {
        //    SAY_FATAL("Context restoration failed miserably %p != %p\n",
        //            sanity_data, data);
        //}

        if (m_is_timeouted) {
            // just skip these samples
            m_is_timeouted = false;
            break;
        }

        uint32_t cov_sz = 0;
        auto cov = m_inst->get_cov(&cov_sz);
        ASSERT(cov && cov_sz);

        auto h = cov_tool::get_cov_hash(cov, cov_sz);
        if (!hashes.size() && !m_cov_tool_bits.is_new_cov_hash(h, false)) {
            // first iteration without new cov
            break;
        }

        if (hashes.size() && hashes.find(h) != hashes.end()) {
            // we found one stable coverage, check it again, with state
            // modification
            if (!m_cov_tool_bits.is_new_cov_hash(h)) {
                // oops, stable cov hash is already processed
                break;
            }
            // we've got new stable hash
            //m_cov_tool_bits.is_new_cov_hash(h);
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
                m_cov_tool_bits.is_new_cov_hash(h);
            }
            if (is_unstable) *is_unstable = true;
        }
    }

    return res;
}

void in_process_fuzzer::save_sample(const uint8_t* data, uint32_t size,
        crash_info* crash) 
{
    if (!m_is_save_samples) return;

    char buf[MAX_PATH];

    auto hash = cov_tool::get_cov_hash(data, size);
    auto hash_str = helper::hex_to_str((const char*)&hash, 
            sizeof(hash));

    if (!crash) {
        static bool dir_checked = false;
        if (!dir_checked) {
            CreateDirectoryA(m_output_corpus_path, 0);
            dir_checked = true;
        }

        snprintf(buf, sizeof(buf), "%s\\%s", m_output_corpus_path,
                hash_str.c_str());
    }
    else {
        static bool dir_checked = false;
        if (!dir_checked) {
            CreateDirectoryA(m_crash_dir, 0);
            dir_checked = true;
        }

        snprintf(buf, sizeof(buf), "%s\\%s_%x_%x_%s.bin", m_crash_dir,
                crash->mod_name.c_str(),
                crash->code, crash->offset,
                hash_str.c_str());
    }

    helper::writeFile(buf, (const char*)data, size, "wb");
}

void in_process_fuzzer::run_one_input(const uint8_t* data, uint32_t size,
        bool save_to_disk) 
{
    ASSERT(data);
    ASSERT(size);
    m_stats.execs++;

    bool is_unstable = false;
    bool should_add_to_corpus = false;
    bool should_save_to_disk = false;
    // stability is judged based on bits not inc
    auto new_hash_by_bits = cov_check_by_hash(data, size, &is_unstable);
    if (m_inst->get_crash_info()->code) {
        auto ci = m_inst->get_crash_info();
        //SAY_INFO("Crashed: %x, sample size: %x, unstable: %d\n", 
        //        ci->code, size, is_unstable);
        { // judge uniqueness by the address of exception
            static std::set<uint32_t> unique_offsets;
            if (unique_offsets.find(ci->offset) == unique_offsets.end()) {
                unique_offsets.insert(ci->offset);
                m_stats.unique_crashes++;
            }
        }
        m_stats.crashes++;

        save_sample(data, size, ci);
        m_inst->clear_crash_info();
    }
    
    if (is_unstable) return;

    if (new_hash_by_bits) {
        if (m_is_hashcov) {
            should_add_to_corpus = true;
        }
        else {
            uint32_t cov_sz = 0;
            uint8_t* cov = 0;
            cov = m_inst->get_cov(&cov_sz);
            if (m_is_bitcov && m_cov_tool_bits.is_new_cov_bits(cov, cov_sz)) {
                m_stats.new_bits++;
                should_add_to_corpus = true;
                should_save_to_disk = true;
            }
            if (m_is_inccov &&
                    m_cov_tool_inc.is_new_greater_byte(cov, cov_sz)) {
                m_stats.new_inc++;
                should_add_to_corpus = true;
            }
        }
    }

    uint32_t cmpcov_sz = 0;
    uint8_t* cmpcov = 0;
    cmpcov = m_inst->get_cmpcov(&cmpcov_sz);

    // cmpcov is bits only, so we con't clear it, we only check for new ones;
    // thus we can use hash to speed up the process
    auto h = cov_tool::get_cov_hash(cmpcov, cmpcov_sz);
    if (m_cov_tool_cmp.is_new_cov_hash(h)) {
        m_stats.cmpcov_bits++;
        should_add_to_corpus = true;
        should_save_to_disk = true;
    }
    // we call this comparison in any case, because we want to have it updated
    //bool is_cmpcov_bits = m_cov_tool_cmp.is_new_cov_bits(cmpcov, cmpcov_sz);
    //if (is_cmpcov_bits) {
    //    m_stats.cmpcov_bits++;
    //    should_add_to_corpus = true;
    //    should_save_to_disk = true;
    //}

    if (should_add_to_corpus) {
        m_mutator.add_sample_to_corpus(data, size);
    }

    if (save_to_disk && should_save_to_disk) {
        // save to disk
        save_sample(data, size);
    }

}

std::vector<std::vector<uint8_t>>
in_process_fuzzer::try_to_fix_strings(uint8_t* data, uint32_t sz)
{
    auto cmps = m_inst->get_strcmpcov();
    auto cmps_sz = cmps->size();

    std::vector<std::vector<uint8_t>> res;

    if (!cmps_sz) return res;

    for (uint32_t ia = 0; ia < cmps_sz; ia++) {
        // find one random failed string comparison
        auto cmpcase = &((*cmps)[ia]);

        //SAY_INFO("%p %x %p %x, sample %p %x\n", 
        //        &cmpcase->buf1[0], cmpcase->buf1.size(),
        //        &cmpcase->buf2[0], cmpcase->buf2.size(),
		//		data, sz);

		// we can try to predict which buffer belongs to the sample, e.g.
        // if there are no printable characters, we can assume that
        uint32_t idx = 1;
        for (uint32_t i = 0; i < 4 && i < cmpcase->buf2.size(); i++) {
            if (cmpcase->buf2[i] >= 0x7f || cmpcase->buf2[i] < 0x20) {
                idx = 0;
                break;
            }
        }
        std::vector<uint8_t>* cmp = &cmpcase->buf2;
        std::vector<uint8_t>* cmp_needed = &cmpcase->buf1;
        if (idx == 0) {
            cmp = &cmpcase->buf1;
            cmp_needed = &cmpcase->buf2;
        }

        bool patched = false;
        for (uint32_t k = 0; k < 2 && !patched; k++) {
            if (k == 1) { // switch buffers on second iteration
                if (cmp == &cmpcase->buf1) {
                    cmp = &cmpcase->buf2;
                    cmp_needed = &cmpcase->buf1;
                }
                else {
                    cmp = &cmpcase->buf1;
                    cmp_needed = &cmpcase->buf2;
                }
            }
            // search the pattern in sample data
            for (uint32_t i = 0; i < sz - cmp->size(); i++) {

                if (!memcmp(&(*cmp)[0], &data[i], cmp->size())) {
                    // we've found the place, at lease we believe so :)
                    //SAY_INFO("offset found: 0x%x\n", i);
                    std::vector<uint8_t> new_sample;
                    new_sample.resize(sz);
                    memcpy(&new_sample[0], data, sz);

                    memcpy(&new_sample[i], &(*cmp_needed)[0], cmp->size());
                    if (cmpcase->should_add_zero &&
                            sz - (cmp->size() + i) >= 1) {
                        new_sample[i + cmp->size()] = 0;
                    }

                    static std::set<std::string> fixed_strings;
                    std::string s = (char*)&new_sample[i];
                    if (fixed_strings.find(s) == fixed_strings.end()) {
                        SAY_INFO("fixed string: %x %x %s\n", i, cmp->size(),
                                &new_sample[i]);
                        fixed_strings.insert(std::move(s));
                        // FIXME:
                        //if (strstr("NIKON", (const char*)&data[i])) {
                        //    helper::writeFile("str_nikon2", (char*)data, sz, "wb");
                        //    memcpy(&data[i], &(*cmp)[0], cmp->size());
                        //    helper::writeFile("str_nikon1", (char*)data, sz, "wb");
                        //}
                    }
                    res.push_back(std::move(new_sample));
                    patched = true;
                    break;
                }
            }
        }
    }
    SAY_INFO("strcmp inputcases: %d, samples patched: %d\n", 
            cmps_sz, res.size());
    return std::move(res);

}

void in_process_fuzzer::run() 
{
    m_thread_ex_thrower = CreateThread(0, 0, _thread_ex_thrower, this, 0, 0);
    if (!m_thread_ex_thrower) {
        SAY_FATAL("Can't create thread, %s\n", 
                helper::getLastErrorAsString().c_str());
    }
    m_thread_id = GetCurrentThreadId();

    process_output_corpus();
    process_input_corpus();

    if (m_cmin_mode) {
        SAY_INFO("Cmin mode, %d samples saved, exiting...\n", 
                m_stats.new_bits);
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
            //restart_if_should();
        }

        //
        // get mutation
        //
        auto new_sample = m_mutator.get_next_mutation();

        m_inst->clear_strcmpcov();
        //
        // run code
        //
        run_one_input(&new_sample[0], new_sample.size());

        // attempt to find and patch strings 


        if (m_stats.execs % 1000 == 0) {
            auto str_samples = try_to_fix_strings(
                    &new_sample[0], new_sample.size());
            for (auto &str_sample: str_samples) {
                run_one_input(&str_sample[0], str_sample.size());
                m_stats.strcmp++;
            }
        }

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
    if (cov_mods.size() != 1) {
        SAY_FATAL("Specify one --cov module\n");
    }

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
        out += cov_mods[0];
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

    auto is_save_samples = GetBinaryOption(
            "--save_samples", argc, argv, true);
    SAY_INFO("save_samples = %d\n", is_show_flow);

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
    if (is_strcmpcov) {
        ins.set_strcmpcov();
    }

    auto fuzz = in_process_fuzzer(&in_proc_harn, &ins);
    vehi.register_handler(&fuzz);
    if (input_dir)
        fuzz.set_input(input_dir);
    if (output_dir)
        fuzz.set_output(output_dir);
    if (crash_dir)
        fuzz.set_crash_dir(crash_dir);
    if (is_cmin)
        fuzz.set_cmin_mode();
    if (zero_corp_sample_size_val)
        fuzz.set_zero_corp_sample_size(zero_corp_sample_size_val);
    if (is_inccov)
        fuzz.set_inccov();
    if (is_bitcov)
        fuzz.set_bitcov();
    if (is_hashcov)
        fuzz.set_hashcov();
    if (is_save_samples) {
        fuzz.set_save_samples();
    }
    if (timeout_v) {
        fuzz.set_timeout(timeout_v);
    }
    fuzz.run();

    ins.print_stats();
    for (auto &addr: libs_resolved) {
        ins.uninstrument(addr);
        FreeLibrary((HMODULE)addr);
    }

    return -1;
}
