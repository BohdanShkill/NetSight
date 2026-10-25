#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_set>
#include <map>

#include "netsight/core/Types.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/ParsedPacket.hpp"

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

TEST(IpAddressTest, FromIPv4AndToString) {
    const std::uint8_t raw[4] = {192, 168, 1, 100};
    const auto ip = IpAddress::from_ipv4(raw);

    EXPECT_TRUE(ip.is_v4());
    EXPECT_FALSE(ip.is_v6());
    EXPECT_TRUE(ip.is_valid());
    EXPECT_EQ(ip.protocol, NetworkProtocol::IPv4);
    EXPECT_EQ(ip.to_string(), "192.168.1.100");
}

TEST(IpAddressTest, FromIPv6AndToString) {
    const std::uint8_t raw[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    const auto ip = IpAddress::from_ipv6(raw);

    EXPECT_FALSE(ip.is_v4());
    EXPECT_TRUE(ip.is_v6());
    EXPECT_TRUE(ip.is_valid());
    EXPECT_EQ(ip.protocol, NetworkProtocol::IPv6);
    EXPECT_EQ(ip.to_string(), "2001:db8:0:0:0:0:0:1");
}

TEST(IpAddressTest, NullPointerSafety) {
    const auto ip4 = IpAddress::from_ipv4(nullptr);
    EXPECT_FALSE(ip4.is_valid());
    EXPECT_EQ(ip4.protocol, NetworkProtocol::None);
    EXPECT_EQ(ip4.to_string(), "None");

    const auto ip6 = IpAddress::from_ipv6(nullptr);
    EXPECT_FALSE(ip6.is_valid());
    EXPECT_EQ(ip6.protocol, NetworkProtocol::None);
    EXPECT_EQ(ip6.to_string(), "None");
}

TEST(IpAddressTest, EqualityAndOrdering) {
    const std::uint8_t raw_a[4] = {10, 0, 0, 1};
    const std::uint8_t raw_b[4] = {10, 0, 0, 2};
    const auto ip_a = IpAddress::from_ipv4(raw_a);
    const auto ip_b = IpAddress::from_ipv4(raw_b);
    const auto ip_a2 = IpAddress::from_ipv4(raw_a);

    EXPECT_EQ(ip_a, ip_a2);
    EXPECT_NE(ip_a, ip_b);
    EXPECT_LT(ip_a, ip_b);

    std::map<IpAddress, std::string> ip_map;
    ip_map[ip_a] = "host_a";
    ip_map[ip_b] = "host_b";
    EXPECT_EQ(ip_map[ip_a], "host_a");
    EXPECT_EQ(ip_map[ip_b], "host_b");
}

TEST(IpAddressTest, HashSupportInUnorderedSet) {
    const std::uint8_t raw[4] = {172, 16, 0, 1};
    const auto ip = IpAddress::from_ipv4(raw);

    std::unordered_set<IpAddress> set;
    set.insert(ip);

    EXPECT_EQ(set.count(ip), 1u);
    EXPECT_EQ(set.count(IpAddress::from_ipv4(nullptr)), 0u);
}

TEST(TcpFlagsTest, IndividualFlags) {
    EXPECT_TRUE(TcpFlags{0x01}.fin());
    EXPECT_TRUE(TcpFlags{0x02}.syn());
    EXPECT_TRUE(TcpFlags{0x04}.rst());
    EXPECT_TRUE(TcpFlags{0x08}.psh());
    EXPECT_TRUE(TcpFlags{0x10}.ack());
    EXPECT_TRUE(TcpFlags{0x20}.urg());
    EXPECT_TRUE(TcpFlags{0x40}.ece());
    EXPECT_TRUE(TcpFlags{0x80}.cwr());

    const TcpFlags syn_ack{0x12};
    EXPECT_TRUE(syn_ack.syn());
    EXPECT_TRUE(syn_ack.ack());
    EXPECT_FALSE(syn_ack.fin());
    EXPECT_FALSE(syn_ack.rst());
}