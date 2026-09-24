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

TEST(ByteOrderTest, NetToHost16_HostToNet16){
    std::uint16_t net_val = 0x1234;
    std::uint16_t expected_host_val = 0x3412;
    EXPECT_EQ(net_to_host_16(net_val), expected_host_val);
    EXPECT_EQ(host_to_net_16(expected_host_val), net_val);
}

TEST(ByteOrderTest, NetToHost32_HostToNet32){
    std::uint32_t net_val = 0x12345678;
    std::uint32_t expected_host_val = 0x78563412;
    EXPECT_EQ(net_to_host_32(net_val), expected_host_val);
    EXPECT_EQ(host_to_net_32(expected_host_val), net_val);
}

TEST(ProtocolToStringTest, AllProtocols){
    EXPECT_EQ(protocol_to_string(ProtocolType::TCP), "TCP");
    EXPECT_EQ(protocol_to_string(ProtocolType::UDP), "UDP");
    EXPECT_EQ(protocol_to_string(ProtocolType::ICMP), "ICMP");
    EXPECT_EQ(protocol_to_string(ProtocolType::ICMPv6), "ICMPv6");
    EXPECT_EQ(protocol_to_string(ProtocolType::Unknown), "Unknown");
}