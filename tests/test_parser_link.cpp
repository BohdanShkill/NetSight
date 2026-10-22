#include <gtest/gtest.h>
#include <type_traits>

#include "netsight/parser/PacketParser.hpp"

using namespace netsight;

static_assert(std::is_trivially_copyable_v<ParsedPacket>,
              "ParsedPacket must be trivially copyable");

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