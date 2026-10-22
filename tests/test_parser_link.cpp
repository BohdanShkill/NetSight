#include <gtest/gtest.h>
#include <type_traits>

#include "netsight/parser/PacketParser.hpp"
#include "support/PacketBuilder.hpp"

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