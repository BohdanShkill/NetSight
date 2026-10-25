#include <gtest/gtest.h>
#include <vector>

#include "netsight/parser/PacketParser.hpp"
#include "support/PacketBuilder.hpp"

using namespace netsight;
using namespace netsight::test;

TEST(ParserNetworkTest, IPv4BasicValid) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 1, 10}, {10, 0, 0, 1}, 6, 64);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.src_ip.to_string(), "192.168.1.10");
    EXPECT_EQ(p.dst_ip.to_string(), "10.0.0.1");
    EXPECT_EQ(p.ip_ttl, 64);
    EXPECT_EQ(p.l3_offset, 14u);
    EXPECT_EQ(p.l4_offset, 34u);
    EXPECT_EQ(p.transport, TransportProtocol::TCP);
    EXPECT_FALSE(p.is_fragment);
    EXPECT_EQ(p.fragment_offset, 0u);
}

TEST(ParserNetworkTest, IPv4WithOptions) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 17, 128, 0, 6);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.l3_offset, 14u);
    EXPECT_EQ(p.l4_offset, 38u);
    EXPECT_EQ(p.transport, TransportProtocol::UDP);
}

TEST(ParserNetworkTest, IPv4TruncatedHeader) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .bytes(11);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserNetworkTest, IPv4TruncatedOptions) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6, 64, 0, 7);

    RawPacket raw = b.build();
    raw.data.resize(14 + 22);

    const ParsedPacket p = parse_packet(raw, LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
}

TEST(ParserNetworkTest, IPv4MalformedVersion) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 0, 1}, {192, 168, 0, 2}, 6, 64, 0, 5, 0, 5);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Malformed);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
}

TEST(ParserNetworkTest, IPv4MalformedIhlTooSmall) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 0, 1}, {192, 168, 0, 2}, 6, 64, 0, 4);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Malformed);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
}

TEST(ParserNetworkTest, IPv4MalformedTotalLength) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 0, 1}, {192, 168, 0, 2}, 6, 64, 15, 5);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Malformed);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
}

TEST(ParserNetworkTest, IPv4FirstFragment) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({10, 1, 1, 1}, {10, 1, 1, 2}, 6, 64, 0, 5, 0x2000);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_TRUE(p.is_fragment);
    EXPECT_EQ(p.fragment_offset, 0u);
    EXPECT_EQ(p.transport, TransportProtocol::TCP);
}

TEST(ParserNetworkTest, IPv4SubsequentFragment) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({10, 1, 1, 1}, {10, 1, 1, 2}, 6, 64, 0, 5, 185);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_TRUE(p.is_fragment);
    EXPECT_EQ(p.fragment_offset, 1480u);
    EXPECT_EQ(p.transport, TransportProtocol::None);
}