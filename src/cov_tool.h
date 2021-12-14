#ifndef _COV_TOOL_
#define _COV_TOOL_

#include <stdint.h>
#include <vector>
#include <set>
#include <xxHash/xxhash.h>

bool operator<(const XXH128_hash_t &x, const XXH128_hash_t &y);

class cov_tool {
    public:
        static XXH128_hash_t get_cov_hash(const uint8_t* cov, uint32_t sz);

        bool is_new_cov_hash(XXH128_hash_t h, bool modify_state = true);
        bool is_new_cov_bits(const uint8_t* cov, uint32_t sz);
        bool is_new_greater_byte(const uint8_t* cov, uint32_t sz);

    private:
        std::vector<uint8_t> m_cov_bits;
        std::set<XXH128_hash_t> m_cov_bits_hashes;
};

#endif // _COV_TOOL_
