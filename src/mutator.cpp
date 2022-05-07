#include "say.h"
#include "mutator.h"
#include <windows.h>

mutator::mutator(mutator_options mo): 
    m_opts(std::move(mo))
{
    m_ticker = m_opts.mode == num_based ?  
        m_ticker = (iticker*)&m_num_ticker :
        m_ticker = (iticker*)&m_time_ticker;
    m_ticker->set_interval(m_opts.mutation_interval);
};

void mutator::add_sample_to_corpus(const uint8_t* data, uint32_t size)
{
    ASSERT(m_corpus.size() == m_mutation_stats.size());

    if (!size) {
        SAY_ERROR("Can't add sample with zero size\n");
        return;
    }

    //SAY_INFO("adding sample -> %p, %x\n", data, size);
    std::vector<uint8_t> s;
    s.resize(size);
    memcpy(&s[0], data, size);
    m_corpus.push_back(std::move(s));

    m_mutation_stats.insert(std::make_pair(0, m_corpus.size() - 1));
}

void mutator::add_sample_to_corpus(std::vector<uint8_t> &sample)
{
    ASSERT(m_corpus.size() == m_mutation_stats.size());

    if (!sample.size()) {
        SAY_ERROR("Can't add sample with zero size\n");
        return;
    }

    m_corpus.push_back(sample);

    m_mutation_stats.insert(std::make_pair(0, m_corpus.size() - 1));
}

size_t i = 0;
void mutator::should_update_index() {
    i++;
    if (m_opts.mode != flat) {
        auto t = m_ticker->tick();
        if (m_cached_sample_idx == -1 || t) {
            update_index_democratic();
            //SAY_INFO("%d iter, update idx, %d %d\n", i, m_cached_sample_idx, t);
        }
    }
    else {
        m_cached_sample_idx = rand() % m_corpus.size();
    }
}

void mutator::update_index_democratic() {
    /*
     * Here we implement "democratic" approach, each sample is mutated equal
     * number of times (or equal amount of time if m_timeMutations is set).
     * This is tracked by multimap.
     */
    size_t r = rand() % m_mutation_stats.size();
    auto first_iter = m_mutation_stats.begin();
    auto prev_mut_counter = (*first_iter).first;

    if (r) {
        for (size_t i = 0; i < r - 1; i++) {
            // SAY_INFO("L: %d / %d, %d %d\n", i, r, firstIter->first,
            //         firstIter->second);
            first_iter++;
            if (prev_mut_counter < first_iter->first) {
                break;
            }
        }
    }

    prev_mut_counter = (*first_iter).first;
    m_cached_sample_idx = (*first_iter).second;
    auto second_iter = next(first_iter);
    m_mutation_stats.erase(first_iter, second_iter);
    m_mutation_stats.insert(
            std::make_pair(prev_mut_counter + m_opts.mutation_interval, 
                m_cached_sample_idx));
}

std::vector<uint8_t> mutator::get_random_sample() {
    auto res_ptr = &m_corpus[rand() % m_corpus.size()];

    std::vector<uint8_t> res;
    res.resize(res_ptr->size());
    memcpy(&res[0], &((*res_ptr)[0]), res.size());
    
    return std::move(res);
}

std::vector<uint8_t> mutator::one_byte_mutation() {

    auto res = get_random_sample();
    auto r1 = rand() % res.size();
    auto r2 = rand();

    res[r1] = r2 & 0xff;

    return std::move(res);

}

std::vector<uint8_t> mutator::regular_mutation() {

    auto res_ptr = &m_corpus[m_cached_sample_idx];
    std::vector<uint8_t> res;
    res.resize(res_ptr->size());
    //SAY_INFO("cached sample idx %d(%d), %p %x\n", m_cachedSampleIdx,
    //        m_corpus.size(), &((*res_ptr)[0]), res_ptr->size());
    memcpy(&res[0], &((*res_ptr)[0]), res.size());

    auto strategy = rand() % 10;

    if (res.size() <= 4) {
        // prohibit some strategies for extemeley small samples
        if (strategy >= 4 && strategy <= 7)
            strategy = 0;
    }

    size_t growSize = 1;
    size_t cutSize = 0;

    if (res.size() / 2 == 0) { // 1 byte long sample

        if (strategy == 9)
            strategy = 0; // can't minimize
    }
    else {

        growSize = rand() % (res.size() / 2); // only for 50% max
        cutSize = rand() % (res.size() / 2);

        // Can't grow more than a limit
        if (res.size() > m_opts.max_sample_size && strategy == 8) {
            strategy = 0;
        }
    }

    size_t count = 0;
    switch (strategy) {

    case 0:
    case 1:
    case 2:
    case 3: // 40%
    {
        /*
         * Byte random patching
         */
        count = res.size() / m_opts.density;
        if (!count)
            count++;

        for (size_t i = 0; i < count; i++) {

            auto r1 = rand() % res.size();
            auto r2 = rand();

            res[r1] = r2 & 0xff;
        }
        break;
    }

    case 4:
    case 5: {
        /*
         * Word random patching
         */
        count = res.size() / (m_opts.density * 2);
        if (!count)
            count++;
        ASSERT(res.size() >= 2);
        size_t maxIdx = res.size() - 1;
        for (size_t i = 0; i < count; i++) {
            *(uint16_t *)&res[rand() % maxIdx] = rand() & 0xffff;
        }
        break;
    }

    case 6:
    case 7: // 20%
    {
        /*
         * DWord random patching
         */
        ASSERT(res.size() >= 4);
        count = res.size() / (m_opts.density * 4);
        size_t maxIdx = res.size() - 3;
        if (!count)
            count++;
        for (size_t i = 0; i < count; i++) {
            int v = rand();
            *(uint32_t *)&res[rand() % maxIdx] = rand();
        }
        break;
    }

    case 8: {
        /*
         * Grow sample
         */
        size_t growOffset = rand() % res.size();
        auto res2 = res;

        // find another sample in corpus with proper size
        size_t fromIdx = 0;
        do {
            fromIdx = rand() % m_corpus.size();
            if (m_corpus[fromIdx].size() > growSize)
                break;
        } while (1);

        auto fromOffset = rand() % (m_corpus[fromIdx].size() - growSize);

        res2.resize(res.size() + growSize);
        // memcpy(&res2[growOffset], &m_corpus[fromIdx][fromOffset], growSize);
        for (size_t j = 0; j < growSize; j++) {
            res2[growOffset + j] = rand() & 0xff;
        }
        size_t lastChunkSize = res.size() - growOffset;
        memcpy(&res2[growOffset + growSize], &res[growOffset], lastChunkSize);
        res = res2;
        break;
    }

    case 9: {
        /*
         * Minimize sample
         */
        size_t newSize = res.size() - cutSize;
        if (!newSize)
            newSize = 1;
        size_t cutOffset = rand() % (res.size() - cutSize);
        memmove(&res[0], &res[cutOffset], cutSize);
        res.resize(newSize);
        break;
    }
    }

    return std::move(res);
}

std::vector<uint8_t> mutator::get_next_mutation() 
{
    if (!m_corpus.size()) {
        SAY_FATAL("GetNext() called on empty corpus");
    }

    should_update_index();

    if (m_opts.mutation_mode == regular) {
        return mutator::regular_mutation();
    }
    else { // if (m_opts.mutation_mode == one_byte_only) {
        return mutator::one_byte_mutation();
    }
}
