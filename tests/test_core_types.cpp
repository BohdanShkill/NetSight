#include <gtest/gtest.h>
#include "netsight/core/Types.hpp"

using namespace netsight;

TEST(RawPacketTest, EmptyPacket){
    RawPacket packet(nullptr, 0, 0);
    EXPECT_TRUE(packet.data.empty());
    EXPECT_EQ(packet.captured_length, 0);
    EXPECT_EQ(packet.original_length, 0);
}

TEST(RawPacketTest, ConstructFromRawBuffer){
    const Byte sample_data[] = {0xDE, 0xAD, 0xBE, 0xBF};
    const std::uint32_t len = 4;
    RawPacket packet(sample_data, len, len );

    EXPECT_EQ(packet.captured_length, len);
    EXPECT_EQ(packet.original_length, len);
    for(uint32_t i = 0; i < len; i++){
        EXPECT_EQ(packet.data[i], sample_data[i]);
    }
}

TEST(RawPacketTest, MoveSemantics){
    const Byte sample_data[] = {0xAA, 0xBB, 0xCC};
    const std::uint32_t len = 3;
    RawPacket packet(sample_data, len, len);

    RawPacket moved = std::move(packet);
    EXPECT_EQ(moved.captured_length, len);
    EXPECT_EQ(moved.original_length, len);
    for(uint32_t i = 0; i < len; i++){
        EXPECT_EQ(moved.data[i], sample_data[i]);
    }
    EXPECT_TRUE(packet.data.empty());
}