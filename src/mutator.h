#ifndef _MUTATOR_H_
#define _MUTATOR_H_

#include <stdint.h>
#include <vector>
#include <map>

class mutator {

    public:
        std::vector<uint8_t> get_next_mutation();
        void add_sample_to_corpus(std::vector<uint8_t> &sample);

    private:
        bool m_timeMutations = false;

        size_t m_cachedSampleIdx = 0;
        size_t m_cachedIterations = -1;

        std::vector<std::vector<uint8_t>> m_corpus;

        size_t m_maxSampleSize = 100000;

        // how much we mutate one sample before switching to another
        size_t m_mutationsAtOnce = 500;
        size_t m_secondsAtOnce = 5;

        size_t m_cachedTick = 0;

        // mapping mutation count to index
        std::multimap<size_t, size_t> m_mutationStats;

        size_t m_density = 32;
};


#endif // _MUTATOR_H_