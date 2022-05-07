#ifndef _MUTATOR_H_
#define _MUTATOR_H_

#include <stdint.h>
#include <vector>
#include <map>
#include "ticker.h"

enum mutation_mode {
    one_byte_only,
    regular,
};

enum mutator_mode {
    // just pick a random sample from corpus and mutate it
    flat,
    // cache one sample for some interval in time
    time_based,
    // cache one sample for some number of iterations
    num_based,
};

struct mutator_options {
    mutator_mode mode = num_based;
    mutation_mode mutation_mode = regular;
    size_t max_sample_size = 100000;
    ULONGLONG mutation_interval = 500; // number or msec
    size_t density = 32; // bytes to mutate = size / density
    
};

class mutator {

    public:
        mutator(mutator_options mo);

        std::vector<uint8_t> get_next_mutation();

        void add_sample_to_corpus(std::vector<uint8_t> &sample);
        void add_sample_to_corpus(const uint8_t* data, uint32_t size);
        size_t get_corpus_size(){ return m_corpus.size(); };
        std::vector<uint8_t> get_random_sample();
        mutator_options clone_opts(){ return m_opts; };

    private:
        void update_index_democratic();
        void should_update_index();
        std::vector<uint8_t> regular_mutation();
        std::vector<uint8_t> one_byte_mutation();

    private:
        size_t m_cached_sample_idx = -1;

        std::vector<std::vector<uint8_t>> m_corpus;

        // mapping mutation count to index
        std::multimap<size_t, size_t> m_mutation_stats;

        // tickers
        time_ticker m_time_ticker;
        num_ticker m_num_ticker;
        iticker* m_ticker = 0;

        mutator_options m_opts;

};


#endif // _MUTATOR_H_
