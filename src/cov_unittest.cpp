#include <gtest/gtest.h>

#include "cov_tool.h"

uint8_t cov0[] = {0, 0, 0, 0, 0, 0, 0, 0};
uint8_t cov1[] = {0, 1, 2, 2, 0, 0, 0, 0};
uint8_t cov2[] = {0, 1, 2, 1, 0, 0, 0, 0};
uint8_t cov3[] = {0, 1, 2, 3, 0, 0, 0, 0};

TEST(cov_tool, bits_check) 
{

    cov_tool ct;
    // zero buffer
    EXPECT_FALSE(ct.is_new_cov_bits(cov0, sizeof(cov0)));
    // new bits introduced
    EXPECT_TRUE(ct.is_new_cov_bits(cov1, sizeof(cov1)));
    // same bits queried
    EXPECT_FALSE(ct.is_new_cov_bits(cov1, sizeof(cov1)));
    // new bits introduced again
    EXPECT_TRUE(ct.is_new_cov_bits(cov2, sizeof(cov2)));
    // zero buffer
    EXPECT_FALSE(ct.is_new_cov_bits(cov0, sizeof(cov0)));
    // no new bits
    EXPECT_FALSE(ct.is_new_cov_bits(cov3, sizeof(cov2)));
}

TEST(cov_tool, greater_check) 
{
    cov_tool ct;
    // zero buffer
    EXPECT_FALSE(ct.is_new_greater_byte(cov0, sizeof(cov0)));
    // new bits introduced
    EXPECT_TRUE(ct.is_new_greater_byte(cov1, sizeof(cov1)));
    // same bits queried
    EXPECT_FALSE(ct.is_new_greater_byte(cov1, sizeof(cov1)));
    // new bits lower values
    EXPECT_FALSE(ct.is_new_greater_byte(cov2, sizeof(cov2)));
    // same bits higher values
    EXPECT_TRUE(ct.is_new_greater_byte(cov3, sizeof(cov3)));
}

TEST(cov_tool, static_hash)
{
    EXPECT_NE(cov_tool::get_cov_hash(cov1, sizeof(cov1)),
            cov_tool::get_cov_hash(cov2, sizeof(cov2)));

    EXPECT_EQ(cov_tool::get_cov_hash(cov1, sizeof(cov1)),
            cov_tool::get_cov_hash(cov1, sizeof(cov1)));

}

TEST(cov_tool, hashes)
{
    auto h0 = cov_tool::get_cov_hash(cov0, sizeof(cov0));
    auto h1 = cov_tool::get_cov_hash(cov1, sizeof(cov1));
    auto h2 = cov_tool::get_cov_hash(cov2, sizeof(cov2));
    auto h3 = cov_tool::get_cov_hash(cov3, sizeof(cov3));

    cov_tool ct;
    EXPECT_TRUE(ct.is_new_cov_hash(h0, true));
    EXPECT_TRUE(ct.is_new_cov_hash(h1, true));
    EXPECT_TRUE(ct.is_new_cov_hash(h2, true));
    EXPECT_TRUE(ct.is_new_cov_hash(h3, true));
    EXPECT_FALSE(ct.is_new_cov_hash(h0, true));
    EXPECT_FALSE(ct.is_new_cov_hash(h1, true));
    EXPECT_FALSE(ct.is_new_cov_hash(h2, true));
    EXPECT_FALSE(ct.is_new_cov_hash(h3, true));
}
