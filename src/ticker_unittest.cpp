#include <gtest/gtest.h>

#include "ticker.h"

TEST(time_ticker, basic_usage) {

  auto tt = time_ticker();
  tt.set_interval(50); // 50ms

  // find first tick
  for (size_t i = 0; i < 100; i++) EXPECT_FALSE(tt.tick());
  Sleep(50);
  EXPECT_TRUE(tt.tick());

  // reset test
  for (size_t i = 0; i < 100; i++) EXPECT_FALSE(tt.tick());
  Sleep(50);
  tt.reset();
  EXPECT_FALSE(tt.tick());
  Sleep(50);
  EXPECT_TRUE(tt.tick());

}

TEST(num_ticker, basic_usage) {

  auto nt = num_ticker();
  nt.set_interval(50);

  // first two true ticks
  for (size_t i = 0; i < 49; i++) EXPECT_FALSE(nt.tick());
  EXPECT_TRUE(nt.tick());
  for (size_t i = 0; i < 49; i++) EXPECT_FALSE(nt.tick());
  EXPECT_TRUE(nt.tick());

}
