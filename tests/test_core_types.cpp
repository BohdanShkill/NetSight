#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>

#include "netsight/core/Types.hpp"

using namespace netsight;

TEST(RawPacketTest, NullPointerSafety) {
    const Timestamp ts{0};
    const RawPacket packet(ts, nullptr, 0, 0);

    EXPECT_TRUE(packet.data.empty());
    EXPECT_EQ(packet.captured_length(), 0u);
    EXPECT_EQ(packet.original_length, 0u);
    EXPECT_EQ(packet.timestamp.count(), 0);
}

TEST(RawPacketTest, ValidPayloadAndTimestamp) {
    const Timestamp ts{1'234'567};
    const std::vector<Byte> expected_payload = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    const RawPacket packet(ts, expected_payload.data(), expected_payload.size(), 5);

    EXPECT_EQ(packet.timestamp, ts);
    EXPECT_EQ(packet.captured_length(), 5u);
    EXPECT_EQ(packet.original_length, 5u);
    EXPECT_EQ(packet.data, expected_payload);
}

TEST(RawPacketTest, TruncatedPacket) {
    const Timestamp ts{500};
    const Byte raw_buffer[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const std::size_t cap_len = 2;
    const std::uint32_t orig_len = 1500;

    const RawPacket packet(ts, raw_buffer, cap_len, orig_len);

    EXPECT_EQ(packet.captured_length(), 2u);
    EXPECT_EQ(packet.original_length, orig_len);
    ASSERT_EQ(packet.data.size(), 2u);
    EXPECT_EQ(packet.data[0], 0xAA);
    EXPECT_EQ(packet.data[1], 0xBB);
}

TEST(RawPacketTest, MoveSemantics) {
    const Timestamp ts{100};
    const Byte sample[] = {0x10, 0x20, 0x30};
    RawPacket source(ts, sample, 3, 3);

    RawPacket destination = std::move(source);

    EXPECT_EQ(destination.captured_length(), 3u);
    EXPECT_EQ(destination.original_length, 3u);
    EXPECT_EQ(destination.timestamp.count(), 100);
    EXPECT_EQ(destination.data.size(), 3u);

    EXPECT_TRUE(source.data.empty());
    EXPECT_EQ(source.captured_length(), 0u);
}

TEST(ByteOrderTest, NetToHost16FromMemory) {
    const std::uint8_t raw_bytes[2] = {0x08, 0x00};
    std::uint16_t raw_word = 0;
    std::memcpy(&raw_word, raw_bytes, sizeof(raw_word));
    EXPECT_EQ(net_to_host_16(raw_word), 0x0800);
}
TEST(ByteOrderTest, NetToHost32FromMemory) {
    const std::uint8_t raw_bytes[4] = {0xC0, 0xA8, 0x01, 0x01};
    std::uint32_t raw_word = 0;
    std::memcpy(&raw_word, raw_bytes, sizeof(raw_word));
    EXPECT_EQ(net_to_host_32(raw_word), 0xC0A80101);
}
TEST(ByteOrderTest, RoundTrip) {
    EXPECT_EQ(net_to_host_16(host_to_net_16(0x1234)), 0x1234);
    EXPECT_EQ(net_to_host_32(host_to_net_32(0xDEADBEEF)), 0xDEADBEEF);
    EXPECT_EQ(host_to_net_32(net_to_host_32(0x12345678)), 0x12345678);
}
TEST(ByteOrderTest, HostToNetWritesBigEndianMemory) {
    const std::uint32_t net_val = host_to_net_32(0x12345678);
    std::uint8_t b[4];
    std::memcpy(b, &net_val, sizeof(b));
    EXPECT_EQ(b[0], 0x12);
    EXPECT_EQ(b[1], 0x34);
    EXPECT_EQ(b[2], 0x56);
    EXPECT_EQ(b[3], 0x78);
}

TEST(StringConversionTest, AllProtocols) {
    EXPECT_EQ(to_string(ProtocolType::Unknown), "Unknown");
    EXPECT_EQ(to_string(ProtocolType::TCP), "TCP");
    EXPECT_EQ(to_string(ProtocolType::UDP), "UDP");
    EXPECT_EQ(to_string(ProtocolType::ICMP), "ICMP");
    EXPECT_EQ(to_string(ProtocolType::ICMPv6), "ICMPv6");
    EXPECT_EQ(to_string(ProtocolType::Other), "Other");
}

TEST(StringConversionTest, AllLinkTypes) {
    EXPECT_EQ(to_string(LinkType::Null), "Null");
    EXPECT_EQ(to_string(LinkType::Ethernet), "Ethernet");
    EXPECT_EQ(to_string(LinkType::Loop), "Loop");
    EXPECT_EQ(to_string(LinkType::LinuxSll), "LinuxSll");
    EXPECT_EQ(to_string(LinkType::Unknown), "Unknown");
}

TEST(LinkTypeTest, TcpdumpNumericEquivalence) {
    EXPECT_EQ(static_cast<std::uint16_t>(LinkType::Null), 0);
    EXPECT_EQ(static_cast<std::uint16_t>(LinkType::Ethernet), 1);
    EXPECT_EQ(static_cast<std::uint16_t>(LinkType::Loop), 108);
    EXPECT_EQ(static_cast<std::uint16_t>(LinkType::LinuxSll), 113);
    EXPECT_EQ(static_cast<std::uint16_t>(LinkType::Unknown), 65535);
}
