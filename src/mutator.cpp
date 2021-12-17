#include "say.h"
#include "mutator.h"
#include <windows.h>

void mutator::add_sample_to_corpus(const uint8_t* data, uint32_t size)
{
    ASSERT(m_corpus.size() == m_mutationStats.size());

    if (!size) {
        SAY_ERROR("Can't add sample with zero size\n");
        return;
    }

    std::vector<uint8_t> s;
    s.resize(size);
    memcpy(&s[0], data, size);
    m_corpus.push_back(s);

    m_mutationStats.insert(std::make_pair(0, m_corpus.size() - 1));
}

void mutator::add_sample_to_corpus(std::vector<uint8_t> &sample)
{

    ASSERT(m_corpus.size() == m_mutationStats.size());

    if (!sample.size()) {
        SAY_ERROR("Can't add sample with zero size\n");
        return;
    }

    m_corpus.push_back(sample);

    m_mutationStats.insert(std::make_pair(0, m_corpus.size() - 1));
}

std::vector<uint8_t> mutator::get_next_mutation() 
{
    if (!m_corpus.size()) {
        SAY_FATAL("GetNext() called on empty corpus");
    }

    /*
     * Here we implement "democratic" approach, each sample is mutated equal
     * amount of times. This is tracked by multimap.
     */

    if (m_timeMutations) {
        bool renewIdx = false;

        if (m_cachedIterations == -1) {
            renewIdx = true;
        }

        size_t currentTick = 0;

        if (m_cachedIterations % 10 == 0) {
            currentTick = GetTickCount64();
            if (currentTick - m_cachedTick > m_secondsAtOnce * 1000) {
                m_cachedIterations = 0;
                m_cachedTick = currentTick;

                renewIdx = true;
            }
        }

        if (renewIdx) {
            if (!currentTick) {
                currentTick = GetTickCount64();
            }

            m_cachedIterations = 0;
            /*
             * Pick random sample with least amount of time and cache it
             */

            size_t r = rand() % m_mutationStats.size();
            auto firstIter = m_mutationStats.begin();
            auto mutationCountPrev = (*firstIter).first;

            if (r) {
                for (size_t i = 0; i < r - 1; i++) {
                    // SAY_INFO("L: %d / %d, %d %d\n", i, r, firstIter->first,
                    //         firstIter->second);
                    firstIter++;
                    if (mutationCountPrev < firstIter->first) {
                        break;
                    }
                }
            }

            mutationCountPrev = (*firstIter).first;
            m_cachedSampleIdx = (*firstIter).second;
            auto secondIter = next(firstIter);
            m_mutationStats.erase(firstIter, secondIter);
            m_mutationStats.insert(std::make_pair(
                mutationCountPrev + m_secondsAtOnce, m_cachedSampleIdx));
            // SAY_INFO("Fuzzing sample %d / %d\n", m_cachedSampleIdx, r);
        }
    }
    else {

        if (m_cachedIterations == m_mutationsAtOnce ||
            m_cachedIterations == -1) {
            m_cachedIterations = 0;

            /*
             * Pick random sample with least amount of time and cache it
             */

            auto firstIter = m_mutationStats.begin();
            auto mutationCountPrev = (*firstIter).first;

            size_t r = rand() % m_mutationStats.size();
            // if (r) {
            //    for (size_t i = 0; i < r - 1; i++) {
            //        // SAY_INFO("L: %d / %d, %d %d\n", i, r, firstIter->first,
            //        //        firstIter->second);
            //        firstIter++
            //        if (mutationCountPrev < firstIter->first) {
            //            break;
            //        }
            //    }
            //}

            mutationCountPrev = (*firstIter).first;
            m_cachedSampleIdx = (*firstIter).second;
            auto secondIter = next(firstIter);
            m_mutationStats.erase(firstIter, secondIter);
            m_mutationStats.insert(std::make_pair(
                mutationCountPrev + m_mutationsAtOnce, m_cachedSampleIdx));
            // SAY_INFO("Fuzzing sample %d / %d\n", m_cachedSampleIdx, r);
        }
    }

    m_cachedIterations++;

    auto res_ptr = &m_corpus[m_cachedSampleIdx];
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

        // Can't grow more than 20k
        if (res.size() > m_maxSampleSize && strategy == 8) {
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
        count = res.size() / m_density;
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
        count = res.size() / (m_density * 2);
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
        count = res.size() / (m_density * 4);
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
        memcpy(&res[0], &res[cutOffset], cutSize);
        res.resize(newSize);
        break;
    }
    }

    return res;
}
