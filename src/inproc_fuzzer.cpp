#include "inproc_fuzzer.h"
#include "say.h"
#include "common.h"

#include <intrin.h>

#define TIMEOUT_CHECK 0x11223301

// We need access to that data during timeout and exception, so it should
// hopefully be valid during the interruption
const uint8_t* g_sanity_data = 0;
uint32_t g_sanity_size = 0;


DWORD inprocess_fuzzer::handle_veh(_EXCEPTION_POINTERS* ex_info) 
{
    if (!m_timeout) { // no timeout set
        return EXCEPTION_CONTINUE_SEARCH;
    }

    auto ex_record = ex_info->ExceptionRecord;
    auto ex_code = ex_record->ExceptionCode;

    auto res = false;
    // check for imeout on OutputDebugString messages
    if (ex_code == TIMEOUT_CHECK) {
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

        res = true;
    }

    return res ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI inprocess_fuzzer::_thread_ex_thrower(LPVOID p)
{
    // The purpose of this this thread is to generate exception every second or
    // so, so we have interruptions at least each second and check hanged 
    // samples in the exception handler
    while(1) {
        Sleep(100);
        RaiseException(TIMEOUT_CHECK, 0, 0, 0);
    }
}

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

void inprocess_fuzzer::process_input_corpus()
{
    auto in_corpus = helper::files_to_vector(m_input_corpus_path);
    SAY_INFO("Processing input corpus (%d samples)...\n", in_corpus.size());
    for (auto &sample: in_corpus) {
        run_one_input(&sample[0], sample.size(), true);
    }

    if (!in_corpus.size()) {
        // no input corpus, put at least something
        std::vector<uint8_t> sample;
        SAY_INFO("zero comp size %d\n", m_zero_corp_sample_size);
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

void inprocess_fuzzer::process_output_corpus()
{
    auto out_corpus = helper::files_to_vector(m_output_corpus_path);
    SAY_INFO("Processing output corpus (%d samples)...\n", out_corpus.size());
    for (auto &sample: out_corpus) {
        run_one_input(&sample[0], sample.size(), false);
    }
}

inprocess_fuzzer::inprocess_fuzzer(
        inprocess_dll_harness* harness, 
        instrumenter* inst,
        uint32_t mutator_density) : 
    m_harness_inproc(harness), 
    m_inst(inst)
{
    m_mutator = mutator();
    if (mutator_density)
        m_mutator.set_density(mutator_density);
}

void inprocess_fuzzer::restart_if_should()
{
    if (m_inst->get_stats()->cpp_exceptions > 500 * 1000) {
        helper::respawn_process(m_argc, m_argv);
    }
}

void inprocess_fuzzer::print_stats(bool force) 
{
    ULONGLONG new_ticks = GetTickCount64();
    if (new_ticks - m_prev_ticks > 1000 * m_stats_sec_timeout || force) {

        ULONGLONG newExecs = m_stats.execs - m_prev_execs;
        auto fcps = (double)newExecs / m_stats_sec_timeout;
        SAY_INFO("%8.2f fcps (%8.2f avg) %10d new bits %10d new inc\n"
                "%10d (%d) crashes, %10d timeouts, %10d total execs, "
                " %10d new execs\n"
                "%10d stable cov, %10d unstable cov, %10d cmpcov bits\n"
                "%10d strcmp\n",
                fcps,
                (double)m_stats.execs / (m_print_stats_count * m_stats_sec_timeout),
                m_stats.new_bits, m_stats.new_inc,
                m_stats.crashes, m_stats.unique_crashes, m_stats.timeouts, 
                m_stats.execs, newExecs,
                m_stats.stable_cov, m_stats.unstable_cov, m_stats.cmpcov_bits,
                m_stats.strcmp
                );
        m_inst->print_stats();

        m_print_stats_count++;
        m_prev_ticks = new_ticks;
        m_prev_execs = m_stats.execs;
    }
}

bool inprocess_fuzzer::cov_check_by_hash(const uint8_t* data, uint32_t size,
        bool* is_unstable) 
{
    bool res = false;
    std::set<XXH128_hash_t> hashes;
    if (is_unstable) *is_unstable = false;

    static size_t cached_ret = 0;
    static uint32_t store_mark = 0;
    static uint32_t continue_mark = 0;
    g_sanity_data = data;
    g_sanity_size = size;

    uint32_t i = 0;
    for (; i < m_stabilize_attempts; i++) {
        // clear coverage
        m_inst->clear_cov();
        // don't need to clear cmpcov because it's only increasing bits
        
        m_start_ticks = GetTickCount64();
        SAY_INFO("call tgt ->\n");

        // WANRING: don't place any new code until restore mark, otherwise
        // adjust offsets in the handle.
        // We need to capture the current context if we need to force
        // continuation of the thread (e.g. timeout or exception)
        if (cached_ret != (size_t)_AddressOfReturnAddress() || true) {
            // FIXME: how to save context without interruption on each 
            // iteration?
            cached_ret = (size_t)_AddressOfReturnAddress();
            __debugbreak();
            store_mark = MARKER_STORE_CONTEXT;
        }
        // run the sample
        m_harness_inproc->call_fuzz_proc((const char*)g_sanity_data, 
                g_sanity_size);
        continue_mark = MARKER_RESTORE_CONTINUE;

        __debugbreak();
        SAY_INFO("call tgt <-\n");
        m_inst->clear_leaks();
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
            // first iteration, no new cov
            break;
        }

        if (hashes.size() && hashes.find(h) != hashes.end()) {
            // we've got new stable hash
            m_stats.stable_cov++;
            m_cov_tool_bits.add_hash(h);
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
    
    if (m_is_timeouted) {
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
                    m_cov_tool_bits.is_new_cov_bits(cov, cov_sz)) {
                m_stats.new_bits++;
                should_add_to_corpus = true;
                should_save_to_disk = true;
            }
            if (m_is_inccov &&
                    m_cov_tool_inc.is_new_greater_byte(cov, cov_sz)) {
                m_stats.new_inc++;
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
        if (m_cov_tool_cmp.is_new_cov_hash(h)) {
            m_stats.cmpcov_bits++;
            should_add_to_corpus = true;
            should_save_to_disk = true;
            // TODO: clear passed cmp cases
        }
    }

    if (should_add_to_corpus) {
        m_mutator.add_sample_to_corpus(data, size);
    }

    if (save_to_disk && should_save_to_disk) {
        // save to disk
        save_sample(data, size);
    }

}

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

void inprocess_fuzzer::run() 
{
    //if (!m_is_hashcov && !m_is_bitcov && !m_is_inccov) {
    //    SAY_FATAL("Specify at least one coverage type\n");
    //}
    
    if (m_timeout) {
        m_thread_ex_thrower = CreateThread(0, 0, _thread_ex_thrower, this, 
                0, 0);
        if (!m_thread_ex_thrower) {
            SAY_FATAL("Can't create thread, %s\n", 
                    helper::getLastErrorAsString().c_str());
        }
        m_thread_id = GetCurrentThreadId();
    }

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

        // get mutation
        auto new_sample = m_mutator.get_next_mutation();

        m_inst->clear_strcmpcov();
        // run code
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

        if (m_stop_on_crash && m_stats.crashes) {
            SAY_INFO("Stopping on crash, last stats:\n");
            print_stats(true);
            break;
        }
        if (m_stop_on_timeout && m_stats.timeouts) {
            SAY_INFO("Stopping on timeout, last stats:\n");
            print_stats(true);
            break;
        }

    }while(1);
}
