#include <gtest/gtest.h>
#include <type_traits>
#include <filesystem>

#include "netsight/parser/PacketParser.hpp"
#include "support/PacketBuilder.hpp"
#include "netsight/source/PcapFileReader.hpp"
#include "support/ReadAll.hpp"

using namespace netsight;
using namespace netsight::test;

static_assert(std::is_trivially_copyable_v<ParsedPacket>,
              "ParsedPacket must be trivially copyable");

TEST(ParserLinkTest, BuilderMatchesHandWrittenBytes) {
    const std::vector<Byte> expected = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x81, 0x00,
        0xA0, 0x64,
        0x08, 0x00
    };
    PacketBuilder builder;
    builder.ethernet(0x8100)
           .vlan(100, 0x0800, /*pcp=*/5);
    const RawPacket packet = builder.build();
    EXPECT_EQ(packet.data, expected);
    EXPECT_EQ(packet.captured_length(), 18u);
}

TEST(ParserLinkTest, UnknownLinkType) {
    const Timestamp ts{100};
    const Byte dummy_data[10] = {0};
    const RawPacket packet(ts, dummy_data, sizeof(dummy_data), 100);

    const ParsedPacket parsed = parse_packet(packet, LinkType::Unknown);

    EXPECT_EQ(parsed.status, ParseStatus::UnsupportedLinkType);
    EXPECT_EQ(parsed.network, NetworkProtocol::None);
    EXPECT_EQ(parsed.timestamp, ts);
    EXPECT_EQ(parsed.wire_length, 100u);
    EXPECT_EQ(parsed.captured_length, 10u);
    EXPECT_EQ(parsed.link_type, LinkType::Unknown);
}

TEST(ParserLinkTest, OutOfEnumLinkType) {
    const Timestamp ts{200};
    const Byte dummy_data[10] = {0};
    const RawPacket packet(ts, dummy_data, sizeof(dummy_data), 100);

    const auto out_of_enum_link = static_cast<LinkType>(276);
    const ParsedPacket parsed = parse_packet(packet, out_of_enum_link);

    EXPECT_EQ(parsed.status, ParseStatus::UnsupportedLinkType);
    EXPECT_EQ(parsed.network, NetworkProtocol::None);
    EXPECT_EQ(parsed.timestamp, ts);
    EXPECT_EQ(parsed.wire_length, 100u);
    EXPECT_EQ(parsed.captured_length, 10u);
    EXPECT_EQ(parsed.link_type, out_of_enum_link);
}

TEST(ParserLinkTest, MetadataSurvivesTruncation) {
    const Timestamp ts{300};
    const Byte dummy_data[10] = {0};
    const RawPacket packet(ts, dummy_data, sizeof(dummy_data), 1500);

    const ParsedPacket parsed = parse_packet(packet, LinkType::Ethernet);

    EXPECT_EQ(parsed.status, ParseStatus::Truncated);
    EXPECT_EQ(parsed.network, NetworkProtocol::None);
    EXPECT_EQ(parsed.wire_length, 1500u);
    EXPECT_EQ(parsed.captured_length, 10u);
    EXPECT_EQ(parsed.timestamp, ts);
    EXPECT_EQ(parsed.link_type, LinkType::Ethernet);
}

TEST(ParserLinkTest, GoldenTcpdumpFileIsEthernetIPv4) {
    const auto pcap_path = std::filesystem::path(NETSIGHT_TEST_DATA_DIR) / "lo_tcp.pcap";
    std::string error;
    auto reader = PcapFileReader::open(pcap_path, error);
    ASSERT_NE(reader, nullptr) << error;
    const auto result = read_all(*reader);
    ASSERT_EQ(result.packets.size(), 10u);
    for (const auto& raw : result.packets) {
        const ParsedPacket p = parse_packet(raw, LinkType::Ethernet);
        EXPECT_EQ(p.status, ParseStatus::Ok);
        EXPECT_EQ(p.network, NetworkProtocol::IPv4);
        EXPECT_EQ(p.ether_type, 0x0800);
        EXPECT_EQ(p.l3_offset, 14u);
        EXPECT_EQ(p.vlan_count, 0u);
    }
}

TEST(ParserLinkTest, EthernetIPv4) {
    PacketBuilder b;
    b.ethernet(0x0800).bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserLinkTest, EthernetIPv6) {
    PacketBuilder b;
    b.ethernet(0x86DD).bytes(40);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
    EXPECT_EQ(p.ether_type, 0x86DD);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserLinkTest, EthernetArp) {
    PacketBuilder b;
    b.ethernet(0x0806).bytes(28);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::Arp);
    EXPECT_EQ(p.ether_type, 0x0806);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserLinkTest, UnknownEtherTypeIsOther) {
    PacketBuilder b;
    b.ethernet(0x88CC).bytes(10);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::Other);
    EXPECT_EQ(p.ether_type, 0x88CC);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserLinkTest, Ieee8023LengthFieldIsOther) {
    PacketBuilder b;
    b.ethernet(0x05DC).bytes(10);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::Other);
    EXPECT_EQ(p.ether_type, 0x05DC);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserLinkTest, TruncatedEthernetHeader) {
    PacketBuilder b;
    b.ethernet(0x0800);
    RawPacket raw = b.build();
    raw.data.resize(13);
    const ParsedPacket p = parse_packet(raw, LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::None);
    EXPECT_EQ(p.captured_length, 13u);
}

TEST(ParserLinkTest, SingleDot1QTag) {
    PacketBuilder b;
    b.ethernet(0x8100)
     .vlan(100, 0x0800)
     .bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.vlan_count, 1u);
    EXPECT_EQ(p.vlan_ids[0], 100u);
    EXPECT_EQ(p.l3_offset, 18u);
}

TEST(ParserLinkTest, QinQTwoTags) {
    PacketBuilder b;
    b.ethernet(0x88A8)
     .vlan(10, 0x8100)
     .vlan(20, 0x0800)
     .bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.vlan_count, 2u);
    EXPECT_EQ(p.vlan_ids[0], 10u);
    EXPECT_EQ(p.vlan_ids[1], 20u);
    EXPECT_EQ(p.l3_offset, 22u);
}

TEST(ParserLinkTest, LegacyQinQ9100) {
    PacketBuilder b;
    b.ethernet(0x9100)
     .vlan(50, 0x0800)
     .bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.vlan_count, 1u);
    EXPECT_EQ(p.vlan_ids[0], 50u);
    EXPECT_EQ(p.l3_offset, 18u);
}

TEST(ParserLinkTest, VidIgnoresPcpAndDei) {
    PacketBuilder b;
    b.ethernet(0x8100)
     .u16_be(0xF00A)
     .u16_be(0x0800)
     .bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.vlan_count, 1u);
    EXPECT_EQ(p.vlan_ids[0], 10u);
    EXPECT_EQ(p.l3_offset, 18u);
}

TEST(ParserLinkTest, ThirdTagIsNotPeeled) {
    PacketBuilder b;
    b.ethernet(0x8100)
     .vlan(1, 0x8100)
     .vlan(2, 0x8100)
     .vlan(3, 0x0800)
     .bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::Other);
    EXPECT_EQ(p.ether_type, 0x8100);
    EXPECT_EQ(p.vlan_count, 2u);
    EXPECT_EQ(p.vlan_ids[0], 1u);
    EXPECT_EQ(p.vlan_ids[1], 2u);
    EXPECT_EQ(p.l3_offset, 22u);
}

TEST(ParserLinkTest, TruncatedInsideVlanTag) {
    PacketBuilder b;
    b.ethernet(0x8100)
     .vlan(100, 0x0800);
    RawPacket raw = b.build();
    raw.data.resize(16);
    const ParsedPacket p = parse_packet(raw, LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::None);
    EXPECT_EQ(p.vlan_count, 0u);
}

TEST(ParserLinkTest, NullLittleEndianIPv4) {
    PacketBuilder b;
    b.null_header(2, false).bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Null);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.l3_offset, 4u);
}

TEST(ParserLinkTest, NullBigEndianIPv4) {
    PacketBuilder b;
    b.null_header(2, true).bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Null);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.l3_offset, 4u);
}

class NullIPv6Test : public ::testing::TestWithParam<uint32_t> {};
TEST_P(NullIPv6Test, NullIPv6AllFamilies) {
    const uint32_t af = GetParam();
    PacketBuilder b;
    b.null_header(af, false).bytes(40);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Null);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
    EXPECT_EQ(p.ether_type, 0x86DD);
    EXPECT_EQ(p.l3_offset, 4u);
}
INSTANTIATE_TEST_SUITE_P(
    IPv6AddressFamilies,
    NullIPv6Test,
    ::testing::Values(24u, 28u, 30u)
);

TEST(ParserLinkTest, NullUnknownFamilyIsOther) {
    PacketBuilder b;
    b.null_header(7, false).bytes(10);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Null);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::Other);
    EXPECT_EQ(p.ether_type, 0u);
    EXPECT_EQ(p.l3_offset, 4u);
}

TEST(ParserLinkTest, LoopIsAlwaysBigEndian) {
    PacketBuilder b_be;
    b_be.null_header(2, true).bytes(20);
    const ParsedPacket p_be = parse_packet(b_be.build(), LinkType::Loop);
    EXPECT_EQ(p_be.status, ParseStatus::Ok);
    EXPECT_EQ(p_be.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p_be.ether_type, 0x0800);
    PacketBuilder b_le;
    b_le.null_header(2, false).bytes(20);
    const ParsedPacket p_le = parse_packet(b_le.build(), LinkType::Loop);
    EXPECT_EQ(p_le.status, ParseStatus::Ok);
    EXPECT_EQ(p_le.network, NetworkProtocol::Other);
    EXPECT_EQ(p_le.ether_type, 0u);
}

TEST(ParserLinkTest, NullTruncated) {
    PacketBuilder b;
    b.bytes(3, 0xAA);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Null);
    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::None);
}

TEST(ParserLinkTest, SllIPv4) {
    PacketBuilder b;
    b.sll(0x0800).bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::LinuxSll);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.l3_offset, 16u);
}

TEST(ParserLinkTest, SllWithVlan) {
    PacketBuilder b;
    b.sll(0x8100)
     .vlan(50, 0x0800)
     .bytes(20);
    const ParsedPacket p = parse_packet(b.build(), LinkType::LinuxSll);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.vlan_count, 1u);
    EXPECT_EQ(p.vlan_ids[0], 50u);
    EXPECT_EQ(p.l3_offset, 20u);
}

TEST(ParserLinkTest, SllNonEtherTypeProtocolIsOther) {
    PacketBuilder b;
    b.sll(0x0004).bytes(10);
    const ParsedPacket p = parse_packet(b.build(), LinkType::LinuxSll);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::Other);
    EXPECT_EQ(p.ether_type, 0x0004);
    EXPECT_EQ(p.l3_offset, 16u);
}

TEST(ParserLinkTest, SllTruncated) {
    PacketBuilder b;
    b.sll(0x0800);
    RawPacket raw = b.build();
    raw.data.resize(15);
    const ParsedPacket p = parse_packet(raw, LinkType::LinuxSll);
    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::None);
    EXPECT_EQ(p.captured_length, 15u);
}