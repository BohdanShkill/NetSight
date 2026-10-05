#include <gtest/gtest.h>
#include "netsight/capture/CaptureConfig.hpp"

TEST(CaptureConfigTest, DefaultInitialization){
    netsight::CaptureConfig config;
    EXPECT_EQ(config.snapshot_length, 65535);
    EXPECT_TRUE(config.promiscuous_mode);
    EXPECT_EQ(config.read_timeout_ms, 1000);
    EXPECT_TRUE(config.bpf_filter.empty()); 
}