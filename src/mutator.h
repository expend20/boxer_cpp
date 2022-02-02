#ifndef _MUTATOR_H_
#define _MUTATOR_H_

#include <stdint.h>
#include <vector>
#include <map>
#include "ticker.h"

enum mutator_mode {
    time_based,
    num_based,
};

struct mutator_options {
    mutator_mode mode = num_based;
    size_t max_sample_size = 100000;
    ULONGLONG mutation_interval = 500; // number or msec
    size_t density = 32; // bytes to mutate = size / density
    
};

class mutator {

    public:
        mutator(mutator_options mo): 
            m_opts(std::move(mo))
        {
            m_ticker = m_opts.mode == num_based ?  
                    m_ticker = (iticker*)&m_num_ticker :
                    m_ticker = (iticker*)&m_time_ticker;
        };

        std::vector<uint8_t> get_next_mutation();

        void add_sample_to_corpus(std::vector<uint8_t> &sample);
        void add_sample_to_corpus(const uint8_t* data, uint32_t size);
        size_t get_corpus_size(){ return m_corpus.size(); };

    private:
        size_t m_cached_sample_idx = 0;

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
