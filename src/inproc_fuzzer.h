#ifndef _INPROC_FUZZ_
#define _INPROC_FUZZ_

#include "inproc_harness.h"
#include "instrumenter.h"
#include "mutator.h"
#include "cov_tool.h"

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

class inprocess_fuzzer: public iveh_handler {
    public: 
        DWORD handle_veh(_EXCEPTION_POINTERS* ex_info) override;
        inprocess_fuzzer(inprocess_dll_harness* harness, 
                instrumenter* inst, uint32_t mutator_density = 0);
        void run();
        bool cov_check_by_hash(const uint8_t* data, uint32_t size, 
                bool* is_unstable);

        void set_input(const char* path);
        void set_output(const char* path);
        void set_crash_dir(const char* path);
        void set_timeout_dir(const char* path);
        void set_cmin_mode(){ m_cmin_mode = true; };
        void set_zero_corp_sample_size(uint32_t v) {
            m_zero_corp_sample_size = v; 
        };
        void set_inccov(){ m_is_inccov = true; };
        void set_hashcov(){ m_is_hashcov = true; };
        void set_bitcov(){ m_is_bitcov = true; };
        void set_save_samples(bool v){ m_is_save_samples = v; };
        void set_timeout(size_t v){ m_timeout = v; };
        void set_argc_argv(int argc, const char** argv){ 
            m_argc = argc; m_argv = argv; };
        void set_stop_on_unique_crash_count(uint32_t v) { 
            m_stop_on_uniq_crash_count = v; 
        };
        void set_stop_on_timeout() { m_stop_on_timeout = true; };
        fuzzer_stats* get_stats() { return &m_stats; };

    private:
        void run_one_input(const uint8_t* data, uint32_t size, 
                bool save_to_disk = true);

        void print_stats(bool force);
        void process_input_corpus();
        void process_output_corpus();
        void restart_if_should();

        std::vector<std::vector<uint8_t>>
            try_to_fix_strings(uint8_t* data, uint32_t sz);

        void save_sample(const uint8_t* data, uint32_t size, 
                crash_info* crash = 0, bool is_timeout = false);

        static DWORD WINAPI _thread_ex_thrower(LPVOID p);

    private:
        inprocess_dll_harness* m_harness_inproc = 0;
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
        const char* m_timeout_dir = 0;
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

        int m_argc = 0;
        const char** m_argv = 0;

        uint32_t m_stop_on_uniq_crash_count = 0;
        bool m_stop_on_timeout = false;

        ULONGLONG m_prev_ticks = GetTickCount64();
        ULONGLONG m_print_stats_count = 1;
        ULONGLONG m_prev_execs = 1;

        uint8_t m_stabilize_attempts = 5;
        std::set<uint32_t> m_unique_offsets;
};

#endif // _INPROC_FUZZ_
