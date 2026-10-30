#include <gtest/gtest.h>
#include "netsight/capture/CaptureConfig.hpp"

TEST(CaptureConfigTest, DefaultInitialization) {
    netsight::CaptureConfig config;
    EXPECT_EQ(config.snapshot_length, 65535);
    EXPECT_TRUE(config.promiscuous_mode);
    EXPECT_EQ(config.read_timeout_ms, 250);
    EXPECT_TRUE(config.bpf_filter.empty());
    EXPECT_EQ(config.buffer_size_bytes, 4 * 1024 * 1024);
}