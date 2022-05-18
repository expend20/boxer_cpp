#ifndef _COV_TOOL_
#define _COV_TOOL_

#include <stdint.h>
#include <vector>
#include <set>
#include <xxHash/xxhash.h>

bool operator<(const XXH128_hash_t &x, const XXH128_hash_t &y);
bool operator==(const XXH128_hash_t &x, const XXH128_hash_t &y);
bool operator!=(const XXH128_hash_t &x, const XXH128_hash_t &y);

class cov_tool {
    public:
        static XXH128_hash_t get_cov_hash(const uint8_t* cov, uint32_t sz);
        static uint32_t count_bytes(const uint8_t* cov, uint32_t sz);

        bool is_new_cov_hash(XXH128_hash_t h, bool modify_state = true);
        bool is_new_cov_bits(const uint8_t* cov, uint32_t sz);
        bool is_new_greater_byte(const uint8_t* cov, uint32_t sz);
        bool is_max_cov_bytes(const uint8_t* cov, uint32_t sz);
        void add_hash(XXH128_hash_t h);
        size_t hashes_size(){ return m_cov_bits_hashes.size(); };
        void clear(){ m_cov_bits.clear(); m_cov_bits_hashes.clear(); };

    private:
        std::vector<uint8_t> m_cov_bits;
        std::set<XXH128_hash_t> m_cov_bits_hashes;
        size_t max_cov_bytes = 0;
};

#endif // _COV_TOOL_
