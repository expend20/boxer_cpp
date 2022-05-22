#include "say.h"
#include "cov_tool.h"

#define ROUND_TO 16
// this is needed by std::set<XXH128_hash_t>
bool operator<(const XXH128_hash_t &x, const XXH128_hash_t &y)
{
    return std::tie(x.low64, x.high64) < std::tie(y.low64, y.high64);
}

bool operator==(const XXH128_hash_t &x, const XXH128_hash_t &y)
{
    return std::tie(x.low64, x.high64) == std::tie(y.low64, y.high64);
}
bool operator!=(const XXH128_hash_t &x, const XXH128_hash_t &y)
{
    return std::tie(x.low64, x.high64) != std::tie(y.low64, y.high64);
}

uint32_t cov_tool::count_bytes(const uint8_t* cov, uint32_t sz)
{
    auto count_bytes = [](const uint8_t* p, uint32_t s) -> uint32_t {
        uint32_t r = 0;
        for (uint32_t i = 0; i < s; i++) {
            if (p[i]) r++;
        }
        return r;
    };
    uint32_t res = 0;
    uint32_t eights = sz / 8;
    auto p_eights = (size_t*)cov;
    for (size_t i = 0; i < eights; i++) {
        if (p_eights[i]) {
            res += count_bytes((const uint8_t*)&p_eights[i], 
                    sizeof(p_eights[0]));
        }
    }
    uint32_t eights_left = sz / 8;
    if (eights_left) {
        res += count_bytes((uint8_t*)&p_eights[eights], sizeof(p_eights[0]));
    }
    return res;
}

bool cov_tool::is_max_cov_bytes(const uint8_t* cov, uint32_t sz) 
{
    // We just check how many bytes (basicblocks) were hit and don't care
    // about anything else
    bool res = false;
    auto n = count_bytes(cov, sz);
    if (n > this->max_cov_bytes) {
        printf("n = %d\n", n);
        this->max_cov_bytes = n;
        res = true;
    }
    return res;
}

bool cov_tool::is_new_greater_byte(const uint8_t* cov, uint32_t sz) 
{
    // if it's first run, shape the buffer
    if (!m_cov_bits.size() || sz > m_cov_bits.size()) {
        m_cov_bits.resize(sz + (ROUND_TO - (sz % ROUND_TO)));
    }
    else {
        // buffer can be shaped only once, but if we dynamically continue 
        // instrumenting the code this is not the case
        // NOTE: during reshaping all previous hashes become invalid
        //ASSERT(m_cov_bits.size() == sz);
    }

    bool res = false;
    uint8_t* p1 = &m_cov_bits[0];
    const uint8_t* p2 = cov;
    for (;
            p2 < (uint8_t*)((size_t)cov + sz);
            p1++, p2++) {
        if (p2[0] > p1[0]) {
            p1[0] = p2[0];
            res = true;
        }
    }

    return res;
}

bool cov_tool::is_new_cov_bits(const uint8_t* cov, uint32_t sz) 
{
    // if it's first run, shape the buffer
    if (!m_cov_bits.size() || sz > m_cov_bits.size()) {
        m_cov_bits.resize(sz + (ROUND_TO - (sz % ROUND_TO)));
    }
    else {
        // buffer can be shaped only once, but if we dynamically continue 
        // instrumenting the code this is not the case
        // NOTE: during reshaping all previous hashes become invalid
        //ASSERT(m_cov_bits.size() == sz);
    }

    bool res = false;
    size_t* p1 = (size_t*)&m_cov_bits[0];
    size_t* p2 = (size_t*)cov;
    for (;
            p2 < (size_t*)((size_t)cov + sz);
            p1++, p2++) {
        if (p2[0] & ~p1[0]) {
            p1[0] |= p2[0];
            res = true;
        }
    }

    return res;
}

XXH128_hash_t cov_tool::get_cov_hash(const uint8_t* cov, uint32_t sz)
{
    XXH3_state_s *const state = XXH3_createState();

    XXH3_128bits_reset(state);

    auto r =
        XXH3_128bits_update(state, (const void *)cov, sz);
    if (r == XXH_ERROR) {
        SAY_FATAL("Hashing error");
    }

    auto res = XXH3_128bits_digest(state);

    XXH3_freeState(state);
    return res;
}

bool cov_tool::is_new_cov_hash(XXH128_hash_t h, bool modify_state)
{
    if (m_cov_bits_hashes.find(h) == m_cov_bits_hashes.end()) {
        if (modify_state) {
            m_cov_bits_hashes.insert(h);
        }
        return true;
    }
    else {
        return false;
    }
}

void cov_tool::add_hash(XXH128_hash_t h)
{
    m_cov_bits_hashes.insert(h);
}
