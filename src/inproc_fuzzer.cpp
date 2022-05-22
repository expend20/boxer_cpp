#include "inproc_fuzzer.h"
#include "say.h"
#include "common.h"

#include <intrin.h>

#define TIMEOUT_CHECK (0x00112233 + 1)

// We need access to that data during timeout and exception, so it should
// hopefully be valid during the interruption
const uint8_t* g_sanity_data = 0;
uint32_t g_sanity_size = 0;
size_t g_sanity_iteration = 0;
size_t g_sanity_mutation = 0;

void inprocess_fuzzer::set_input(const char* path)
{
    ASSERT(path);
    m_input_corpus_path = path;
}

void inprocess_fuzzer::set_output(const char* path)
{
    ASSERT(path);
    m_output_corpus_path = path;
}

void inprocess_fuzzer::set_crash_dir(const char* path)
{
    ASSERT(path);
    m_crash_dir = path;
}

void inprocess_fuzzer::set_timeout_dir(const char* path)
{
    ASSERT(path);
    m_timeout_dir = path;
}

void inprocess_fuzzer::assure_input_samples() {

    if (!m_mutator.get_corpus_size()) {
        // no input corpus, put at least something
        std::vector<uint8_t> sample;
        SAY_INFO("Fake sample size %d\n", m_zero_corp_sample_size);
        sample.resize(m_zero_corp_sample_size);

        for (uint32_t i = 0; i < sample.size(); i++) {
            sample[i] = rand() % 256;
        }
        run_one_input(&sample[0], sample.size(), true, m_nocov_mode);
    }

    if (!m_mutator.get_corpus_size()) {
        SAY_FATAL("No valid input samples, meaning no sample produced any "
                "coverage, revisit your parameters\n");
    }
}

ULONGLONG inprocess_fuzzer::get_elapsed_seconds() {
    return (GetTickCount64() - m_session_start_time) / 1000;
}

void inprocess_fuzzer::process_input_corpus()
{
    if (m_runner_thread_opts.is_input_processed) {
        SAY_INFO("Input is already processed\n");
        return;
    }

    // statefull function (it can survive restarts on timeout/crashes)
    if (!m_in_corpus.size()) {
        m_in_corpus = helper::files_to_vector(m_input_corpus_path);
    }

    size_t i = 0;
    size_t in_corpus_size = m_in_corpus.size();
    size_t in_corpus_size_10th = m_in_corpus.size() / 10;

    SAY_INFO("Processing input corpus (%d samples)...\n", in_corpus_size);

    while (m_in_corpus.size()) {
        if (in_corpus_size_10th && (i++ % in_corpus_size_10th == 0)) {
            SAY_INFO("%d / %d, elapsed %llu seconds\n", 
                    i, in_corpus_size, get_elapsed_seconds());
        }

        auto sample = std::move(m_in_corpus.back());
        m_in_corpus.pop_back();

        if (m_in_corpus.size() == 0) 
            m_runner_thread_opts.is_input_processed = true;

        run_one_input(&sample[0], sample.size(), true, m_nocov_mode);
    }

}

void inprocess_fuzzer::process_output_corpus()
{
    if (m_runner_thread_opts.is_output_processed) {
        SAY_INFO("Output is already processed\n");
        return;
    };

    if (!m_out_corpus.size()) {
        m_out_corpus = helper::files_to_vector(m_output_corpus_path);
        if (!m_out_corpus.size()) {
            SAY_INFO("No files were read from output corpus\n");
            m_runner_thread_opts.is_output_processed = true;
            return;
        }
    }

    size_t i = 0;
    size_t corpus_size = m_out_corpus.size();
    size_t corpus_size_10th = m_out_corpus.size() / 10;

    SAY_INFO("Processing output corpus (%d samples)...\n", corpus_size);
    while (m_out_corpus.size()) {
        auto sample = std::move(m_out_corpus.back());
        m_out_corpus.pop_back();

        if (m_out_corpus.size() == 0) 
            m_runner_thread_opts.is_output_processed = true;

        if (corpus_size_10th && (i++ % corpus_size_10th == 0)) {
            SAY_INFO("%d / %d, elapsed %llu seconds\n", i, corpus_size,
                    get_elapsed_seconds());
        }
        run_one_input(&sample[0], sample.size(), false);
    }
}

inprocess_fuzzer::inprocess_fuzzer(
        mutator mut,
        inprocess_dll_harness* harness, 
        instrumenter* inst) : 
    m_harness_inproc(harness), 
    m_inst(inst),
    m_mutator(std::move(mut))
{
}

void inprocess_fuzzer::restart_if_should()
{
    if (m_inst->get_stats()->cpp_exceptions > 500 * 1000) {
        helper::respawn_process(m_argc, m_argv);
    }
}

#include <cmath>

void inprocess_fuzzer::print_stats(bool force) 
{
    ULONGLONG new_ticks = GetTickCount64();
    if (new_ticks - m_prev_ticks > 1000 * m_stats_sec_timeout || force) {

        ULONGLONG newExecs = m_stats.execs - m_prev_execs;
        auto fcps = (double)newExecs / m_stats_sec_timeout;
        auto t = get_elapsed_seconds();
        auto hours = t / (60 * 60);
        auto minutes = (t % (60 * 60)) / 60;
        auto seconds = t % 60;
        SAY_INFO("%8.2f fcps (%8.2f avg) %10llu new bits %10llu new inc, "
                "%8llu:%02llu:%02llu from start\n"
                "%10llu (%llu) crashes, %10llu timeouts, %10llu total execs, "
                " %10llu new execs\n"
                "%10lu stable cov, %10llu unstable cov, %10llu cmpcov bits\n"
                "%10llu strcmp %10u mutator corp\n",
                fcps,
                (double)m_stats.execs / (m_print_stats_count * 
                    m_stats_sec_timeout),
                m_stats.new_bits, m_stats.new_inc,
                hours, minutes, seconds,
                m_stats.crashes, m_stats.unique_crashes, m_stats.timeouts, 
                m_stats.execs, newExecs,
                m_cov_bits_total.hashes_size(), m_stats.unstable_cov, 
                m_stats.cmpcov_bits,
                m_stats.strcmp, m_mutator.get_corpus_size()
                );
        m_inst->print_stats();

        m_print_stats_count++;
        m_prev_ticks = new_ticks;
        m_prev_execs = m_stats.execs;
    }
}

extern "C" void __fastcall save_context(_CONTEXT* ctx);
void __declspec(noinline) inprocess_fuzzer::call_proc() {
    auto r = m_inst->get_restore_ctx();
    save_context(r);
    // run the sample
    m_harness_inproc->call_fuzz_proc((const char*)g_sanity_data, 
            g_sanity_size);
    // this is code marker:
    __nop();
}

bool inprocess_fuzzer::cov_check_by_hash(const uint8_t* data, uint32_t size,
        bool* is_unstable) 
{
    bool res = false;
    std::set<XXH128_hash_t> hashes;
    if (is_unstable) *is_unstable = false;

    static size_t cached_ret = 0;
    static uint32_t store_mark = 0;
    g_sanity_data = data;
    g_sanity_size = size;

    uint32_t i = 0;
    for (; i < m_stabilize_attempts; i++) {
        // clear coverage
        m_inst->clear_cov();
        // don't need to clear cmpcov because it's only increasing bits

        g_sanity_iteration++;
        
        // ticks are needed by timeout only
        m_start_ticks = GetTickCount64();

        call_proc();

        m_start_ticks = 0;

        m_inst->clear_leaks();

        uint32_t cov_sz = 0;
        auto cov = m_inst->get_cov(&cov_sz);
        ASSERT(cov && cov_sz);

        auto h = cov_tool::get_cov_hash(cov, cov_sz);
        if (!hashes.size() && !m_cov_bits_total.is_new_cov_hash(h, false)) {
            // first iteration, no new cov found
            break;
        }

        if (hashes.size() && hashes.find(h) != hashes.end()) {
            // we've got new stable hash
            m_cov_bits_total.add_hash(h);
            res = true;
            break;
        }
        hashes.insert(h);
    }
    if (i == m_stabilize_attempts) {
        m_stats.unstable_cov++;

        if (is_unstable) *is_unstable = true;
    }

    return res;
}

void inprocess_fuzzer::save_sample(const uint8_t* data, uint32_t size,
        crash_info* crash, bool is_timeout) 
{
    if (!m_is_save_samples) return;

    char buf[MAX_PATH];

    auto hash = cov_tool::get_cov_hash(data, size);
    auto hash_str = helper::hex_to_str((const char*)&hash, 
            sizeof(hash));

    if (is_timeout) {
        if (!m_timeout_dir) return;

        static bool dir_checked = false;
        if (!dir_checked) {
            CreateDirectoryA(m_timeout_dir, 0);
            dir_checked = true;
        }
        snprintf(buf, sizeof(buf), "%s\\%s", m_timeout_dir,
                hash_str.c_str());
        SAY_INFO("saving sample %s\n", buf);
    }
    else if (!crash) {
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

void inprocess_fuzzer::run_one_input(const uint8_t* data, uint32_t size,
        bool save_to_disk, bool force_add_sample) 
{
    ASSERT(data);
    ASSERT(size);
    m_stats.execs++;

    bool is_unstable = false;
    bool should_add_to_corpus = false;
    bool should_save_to_disk = false;
    // stability is judged based on bits not inc
    auto new_hash_by_bits = cov_check_by_hash(data, size, &is_unstable);

    if (m_nocov_mode && !force_add_sample) {
        // don't waste time on checks becase we're in nocov mode
        // this is also useful when we want to fuzz only input samples with 
        // coverage enabled to measure perf
        return;
    }
    
    if (m_is_timeouted) {
        SAY_INFO("Timeouted sample...\n");
        save_sample(data, size, 0, true);
        m_is_timeouted = false;
        return;
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
            if (m_is_bitcov && 
                    m_cov_bits_total.is_new_cov_bits(cov, cov_sz)) {
                m_stats.new_bits++;
                should_add_to_corpus = true;
                should_save_to_disk = true;
            }
            if (m_is_inccov &&
                    m_cov_inc_total.is_new_greater_byte(cov, cov_sz)) {
                m_stats.new_inc++;
                should_add_to_corpus = true;
                should_save_to_disk = true;
            }
            if (m_is_maxcov &&
                    m_cov_max_total.is_max_cov_bytes(cov, cov_sz)) {
                should_add_to_corpus = true;
                should_save_to_disk = true;
            }
        }
    }

    uint32_t cmpcov_sz = 0;
    uint8_t* cmpcov = 0;
    cmpcov = m_inst->get_cmpcov(&cmpcov_sz);

    // cmpcov is bits only, so we may not clear it, we only check for new ones;
    // thus we can use hash to speed up the process
    if (cmpcov_sz) {
        auto h = cov_tool::get_cov_hash(cmpcov, cmpcov_sz);
        if (m_cov_cmp_total.is_new_cov_hash(h)) {
            m_stats.cmpcov_bits++;
            should_add_to_corpus = true;
            should_save_to_disk = true;

            // clear passed cmp cases
            m_inst->clear_passed_cmpcov_code();
        }
    }

    if (should_add_to_corpus || force_add_sample) {
        m_mutator.add_sample_to_corpus(data, size);
    }

    if (save_to_disk && should_save_to_disk) {
        // save to disk
        save_sample(data, size);
    }

}

// TODO: refactor buggy func
std::vector<std::vector<uint8_t>>
inprocess_fuzzer::try_to_fix_strings(uint8_t* data, uint32_t sz)
{
    auto cmps = m_inst->get_strcmpcov();
    auto cmps_sz = cmps->size();

    std::vector<std::vector<uint8_t>> res;
    if (!cmps_sz) return res;

    for (uint32_t ia = 0; ia < cmps_sz; ia++) {
        // find one random failed string comparison
        auto cmpcase = &((*cmps)[ia]);

        //SAY_INFO("try to fix strings: %p 0x%x %p 0x%x, sample %p 0x%x\n", 
        //        &cmpcase->buf1[0], cmpcase->buf1.size(),
        //        &cmpcase->buf2[0], cmpcase->buf2.size(),
		//		data, sz);

		// we can try to predict which buffer belongs to the sample, e.g.
        // if there are no printable characters, we can assume that
        uint32_t idx = 0;
        for (uint32_t i = 0; i < 4 && i < cmpcase->buf2.size(); i++) {
            if (cmpcase->buf2[i] && 
                    (cmpcase->buf2[i] >= 0x7f || cmpcase->buf2[i] < 0x20)) {
                idx = 1;
                break;
            }
        }
        std::vector<uint8_t>* cmp = &cmpcase->buf2;
        std::vector<uint8_t>* cmp_needed = &cmpcase->buf1;
        if (idx == 0) {
            cmp = &cmpcase->buf1;
            cmp_needed = &cmpcase->buf2;
            //SAY_INFO("idx is first\n");
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
            //SAY_INFO("Searching pattern %d in buf %p 0x%x\n", k,
            //        &(*cmp)[0], cmp->size());

            // search the pattern in sample data
            if (sz < cmp->size()) {
                //SAY_ERROR("sz < cmp->size(), 0x%x vs 0x%x\n", sz, cmp->size());
                continue;
            }
            for (uint32_t i = 0; i < sz - cmp->size() + 1; i++) {

                //SAY_INFO("memcmp %p %p 0x%x | i 0x%x, sz 0x%x\n", 
                //        &(*cmp)[0], &data[i], cmp->size(),
                //        i, sz);
                if (!memcmp(&(*cmp)[0], &data[i], cmp->size())) {
                    // we've found the place, at lease we believe so :)
                    //SAY_INFO("offset found: 0x%x\n", i);
                    std::vector<uint8_t> new_sample;
                    // new size could be bigger than original one
                    auto new_sz = cmp_needed->size() > sz - i ?
                        i + cmp_needed->size() : sz;

                    new_sample.resize(new_sz);
                    memcpy(&new_sample[0], data, sz);

                    //SAY_INFO("Writing at %p offset 0x%x 0x%x bytes, buf %p\n", 
                    //        &new_sample[0], i, cmp_needed->size(), &(*cmp_needed)[0]);
                    memcpy(&new_sample[i], &(*cmp_needed)[0], 
                            cmp_needed->size());
                    //SAY_INFO("Write ok\n");

                    res.push_back(std::move(new_sample));
                    patched = true;
                    break;
                }
            }
        }
    }
    //SAY_INFO("strcmp inputcases: %d, samples patched: %d\n", 
    //        cmps_sz, res.size());
    return std::move(res);

}

void inprocess_fuzzer::run_session()
{
    SAY_INFO("Running fuzzing session...\n");
    do { 
        if (m_stats.execs % 10 == 0) {
            print_stats(false);
            //restart_if_should();
        }

        // get mutation
        g_sanity_mutation++;
        auto new_sample = m_mutator.get_next_mutation();

        m_inst->clear_strcmpcov();
        // run code
        //SAY_INFO("sample %p 0x%x\n", &new_sample[0], new_sample.size());
        run_one_input(&new_sample[0], new_sample.size());

        auto str_samples = try_to_fix_strings(
                &new_sample[0], new_sample.size());
        for (auto &str_sample: str_samples) {
            //SAY_INFO("%p %x", &str_sample[0], str_sample.size());
            run_one_input(&str_sample[0], str_sample.size());
            m_stats.strcmp++;
        }

    } while(1);
}

DWORD WINAPI inprocess_fuzzer::_runner_thread(LPVOID p)
{
    SAY_INFO("Runner thread spawned\n");

    CoInitialize(0);

    auto _this = (inprocess_fuzzer*)p;

    auto opts = &_this->m_runner_thread_opts;

    _this->process_output_corpus();
    _this->process_input_corpus();

    _this->assure_input_samples();

    if (_this->m_cmin_mode) {
        SAY_INFO("Cmin mode, %d samples saved, exiting...\n", 
                _this->m_stats.new_bits);
        return 1;
    }

    _this->run_session();
    return 0;
}


void inprocess_fuzzer::run() 
{
    HANDLE thread = INVALID_HANDLE_VALUE;
    m_session_start_time = GetTickCount64();

    while(1) {
        // create thrad if not yet created
        if (thread == INVALID_HANDLE_VALUE) {
            SAY_INFO("Creating runner thread...\n");
            thread = CreateThread(0, 0, _runner_thread, this, 0, 0);
            if (!thread) {
                SAY_FATAL("Can't create thread, %s\n", 
                        helper::getLastErrorAsString().c_str());
            }
        }

        DWORD exit_code = STILL_ACTIVE;
        auto cur_time = GetTickCount64();

        // check for crash
        if (m_inst->get_crash_info()->code) {
            SAY_INFO("crash detected\n");
            auto ci = m_inst->get_crash_info();
            //SAY_INFO("Crashed: %x, sample size: %x, unstable: %d\n", 
            //        ci->code, size, is_unstable);
            { // judge uniqueness by the address of exception
                static std::set<uint32_t> unique_offsets;
                if (m_unique_offsets.find(ci->offset) == m_unique_offsets.end()) {
                    m_unique_offsets.insert(ci->offset);
                    m_stats.unique_crashes++;
                }
            }
            m_stats.crashes++;
            save_sample(g_sanity_data, g_sanity_size, ci);
            m_inst->clear_crash_info();

            if (!TerminateThread(thread, -1)) {
                SAY_FATAL("Can't terminate thread, %s\n", 
                        helper::getLastErrorAsString().c_str());
            }
            thread = INVALID_HANDLE_VALUE;

            if (m_stop_on_uniq_crash_count && 
                    m_stats.unique_crashes >= m_stop_on_uniq_crash_count) {
                SAY_INFO("Stopping on crash (%d), last stats:\n",
                        m_stats.unique_crashes);
                print_stats(true);
                break;
            }
        }
        // check if thread is still alive
        else if (!GetExitCodeThread(thread, &exit_code)) {
            SAY_FATAL("Can't get exit code of thread, %x %s\n", thread,
                    helper::getLastErrorAsString().c_str());
        }
        else if (exit_code != STILL_ACTIVE) {
            SAY_ERROR("Thread exited for some reason %x, code %d\n", thread,
                    exit_code);
            __debugbreak();
            break;
        }
        // check for timeout and terminate thread if need
        else if (m_start_ticks && cur_time - m_start_ticks > m_timeout) {

            save_sample(g_sanity_data, g_sanity_size, 0, true);
            SAY_INFO("timeout detected, %llu %llu %llu %llu exiting "
                    "thread...\n",
                    m_start_ticks, cur_time, 
                    cur_time - m_start_ticks, m_timeout);
            m_start_ticks = 0;

            if (!TerminateThread(thread, -1)) {
                SAY_FATAL("Can't terminate thread, %s\n", 
                        helper::getLastErrorAsString().c_str());
            }
            thread = INVALID_HANDLE_VALUE;
            m_stats.timeouts++;

            if (m_stop_on_timeout) {
                SAY_INFO("Stopping on timeout, last stats:\n");
                print_stats(true);
                break;
            }
        }
        

        if (thread != INVALID_HANDLE_VALUE) {
            Sleep(1000);
        }
    }
}

