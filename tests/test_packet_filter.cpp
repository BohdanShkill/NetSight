#include <gtest/gtest.h>
#include <array>
#include <cstdint>

#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "netsight/pipeline/PacketFilter.hpp"
#include "support/PacketBuilder.hpp"

using namespace netsight;
using namespace netsight::test;

TEST(PacketFilterTest, EmptyFilterMatchesEverything) {
    const PacketFilter filter{};
    EXPECT_TRUE(filter.empty());

    const auto raw_tcp = PacketBuilder{}.ethernet(0x0800).ipv4().tcp(1234, 80).build();
    const auto parsed_tcp = parse_packet(raw_tcp, LinkType::Ethernet);
    EXPECT_TRUE(filter.matches(parsed_tcp));

    const auto raw_arp = PacketBuilder{}.ethernet(0x0806).bytes(28, 0).build();
    const auto parsed_arp = parse_packet(raw_arp, LinkType::Ethernet);
    EXPECT_TRUE(filter.matches(parsed_arp));

    const auto raw_bad = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6, 64, 100).build();
    const auto parsed_bad = parse_packet(raw_bad, LinkType::Ethernet);
    EXPECT_TRUE(filter.matches(parsed_bad));

    const auto parsed_unsupported = parse_packet(raw_tcp, LinkType::Unknown);
    EXPECT_TRUE(filter.matches(parsed_unsupported));
}

TEST(PacketFilterTest, IpMatchesSrcOrDst) {
    PacketFilter filter{};
    filter.ip = parse_ip_address("10.0.0.1");
    EXPECT_FALSE(filter.empty());

    const auto raw_src = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {192, 168, 1, 1}).tcp().build();
    EXPECT_TRUE(filter.matches(parse_packet(raw_src, LinkType::Ethernet)));

    const auto raw_dst = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {10, 0, 0, 1}).tcp().build();
    EXPECT_TRUE(filter.matches(parse_packet(raw_dst, LinkType::Ethernet)));

    const auto raw_other = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}).tcp().build();
    EXPECT_FALSE(filter.matches(parse_packet(raw_other, LinkType::Ethernet)));
}

TEST(PacketFilterTest, IpFilterRejectsNonIpAndOtherFamily) {
    PacketFilter filter_v4{};
    filter_v4.ip = parse_ip_address("10.0.0.1");

    const auto raw_arp = PacketBuilder{}.ethernet(0x0806).bytes(28, 0).build();
    EXPECT_FALSE(filter_v4.matches(parse_packet(raw_arp, LinkType::Ethernet)));

    const auto raw_ipv6 = PacketBuilder{}.ethernet(0x86DD).ipv6().tcp().build();
    EXPECT_FALSE(filter_v4.matches(parse_packet(raw_ipv6, LinkType::Ethernet)));

    PacketFilter filter_v6{};
    filter_v6.ip = parse_ip_address("2001:db8::1");

    const auto raw_ipv4 = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 2}).tcp().build();
    EXPECT_FALSE(filter_v6.matches(parse_packet(raw_ipv4, LinkType::Ethernet)));
}

TEST(PacketFilterTest, PortMatchesSrcOrDstForTcpAndUdp) {
    PacketFilter filter{};
    filter.port = 53;

    const auto raw_udp_dst = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 17).udp(5000, 53).payload("dns").build();
    EXPECT_TRUE(filter.matches(parse_packet(raw_udp_dst, LinkType::Ethernet)));

    const auto raw_udp_src = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 17).udp(53, 5000).payload("dns").build();
    EXPECT_TRUE(filter.matches(parse_packet(raw_udp_src, LinkType::Ethernet)));

    const auto raw_tcp_80 = PacketBuilder{}.ethernet(0x0800).ipv4().tcp(1234, 80).build();
    EXPECT_FALSE(filter.matches(parse_packet(raw_tcp_80, LinkType::Ethernet)));

    const auto raw_tcp_53 = PacketBuilder{}.ethernet(0x0800).ipv4().tcp(53, 1234).build();
    EXPECT_TRUE(filter.matches(parse_packet(raw_tcp_53, LinkType::Ethernet)));
}

TEST(PacketFilterTest, PortIgnoresIcmpFragmentsAndTruncatedTcp) {
    PacketFilter filter{};
    filter.port = 80;

    const auto raw_icmp = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 1).icmp(8, 0).build();
    EXPECT_FALSE(filter.matches(parse_packet(raw_icmp, LinkType::Ethernet)));

    const auto raw_frag = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 6, 64, 0, 5, 0x0064).bytes(20, 0).build();
    const auto parsed_frag = parse_packet(raw_frag, LinkType::Ethernet);
    EXPECT_TRUE(parsed_frag.is_fragment);
    EXPECT_FALSE(filter.matches(parsed_frag));

    const auto raw_trunc = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 6).bytes(10, 0).build();
    const auto parsed_trunc = parse_packet(raw_trunc, LinkType::Ethernet);
    EXPECT_EQ(parsed_trunc.status, ParseStatus::Truncated);
    EXPECT_FALSE(filter.matches(parsed_trunc));
}

TEST(PacketFilterTest, PortMatchesInsideVlan) {
    PacketFilter filter{};
    filter.port = 80;

    const auto raw_vlan = PacketBuilder{}.ethernet(0x8100).vlan(100, 0x0800).ipv4().tcp(54321, 80).build();
    const auto parsed_vlan = parse_packet(raw_vlan, LinkType::Ethernet);
    EXPECT_EQ(parsed_vlan.status, ParseStatus::Ok);
    EXPECT_EQ(parsed_vlan.vlan_count, 1);
    EXPECT_EQ(parsed_vlan.vlan_ids[0], 100);
    EXPECT_TRUE(filter.matches(parsed_vlan));
}

TEST(PacketFilterTest, IpAndPortAreAnded) {
    PacketFilter filter{};
    filter.ip = parse_ip_address("10.0.0.1");
    filter.port = 80;

    const auto raw_match = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {192, 168, 1, 1}).tcp(12345, 80).build();
    EXPECT_TRUE(filter.matches(parse_packet(raw_match, LinkType::Ethernet)));

    const auto raw_ip_only = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {192, 168, 1, 1}).tcp(12345, 443).build();
    EXPECT_FALSE(filter.matches(parse_packet(raw_ip_only, LinkType::Ethernet)));

    const auto raw_port_only = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 2}, {192, 168, 1, 1}).tcp(12345, 80).build();
    EXPECT_FALSE(filter.matches(parse_packet(raw_port_only, LinkType::Ethernet)));
}