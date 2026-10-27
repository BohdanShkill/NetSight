#include <gtest/gtest.h>
#include <vector>
#include <filesystem>

#include "netsight/parser/PacketParser.hpp"
#include "support/PacketBuilder.hpp"
#include "netsight/source/PcapFileReader.hpp"
#include "support/ReadAll.hpp"

using namespace netsight;
using namespace netsight::test;

TEST(ParserNetworkTest, IPv4BasicValid) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 1, 10}, {10, 0, 0, 1}, 6, 64)
     .tcp(1234, 80);
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
     .ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 17, 128, 0, 6)
     .udp(53, 53);

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
     .ipv4({10, 1, 1, 1}, {10, 1, 1, 2}, 6, 64, 0, 5, 0x2000)
     .tcp(80, 8000);
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

TEST(ParserNetworkTest, IPv6TcpValid) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
           6, 64)
     .tcp(80, 443);
    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
    EXPECT_EQ(p.src_ip.to_string(), "2001:db8:0:0:0:0:0:1");
    EXPECT_EQ(p.dst_ip.to_string(), "2001:db8:0:0:0:0:0:2");
    EXPECT_EQ(p.ip_ttl, 64);
    EXPECT_EQ(p.l3_offset, 14u);
    EXPECT_EQ(p.l4_offset, 54u);
    EXPECT_EQ(p.transport, TransportProtocol::TCP);
    EXPECT_FALSE(p.is_fragment);
}

TEST(ParserNetworkTest, IPv6MalformedVersion) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
           6, 64, 0, 4);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Malformed);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
}

TEST(ParserNetworkTest, IPv6TruncatedHeader) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .bytes(35);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
    EXPECT_EQ(p.l3_offset, 14u);
}

TEST(ParserNetworkTest, IPv6WithHopByHopOption) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
           0, 64)
     .ipv6_ext_header(17, 0, {0, 0, 0, 0, 0, 0})
     .udp(53, 53);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
    EXPECT_EQ(p.transport, TransportProtocol::UDP);
    EXPECT_EQ(p.l3_offset, 14u);
    EXPECT_EQ(p.l4_offset, 62u);
}

TEST(ParserNetworkTest, IPv6FragmentHeaderNonFirst) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
           44, 64)
     .ipv6_fragment(6, 800, false);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_TRUE(p.is_fragment);
    EXPECT_EQ(p.fragment_offset, 800u);
    EXPECT_EQ(p.transport, TransportProtocol::None);
}

TEST(ParserNetworkTest, IPv6ExtensionHeaderLoopProtection) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
           60, 64);

    for (int i = 0; i < 9; ++i) {
        b.ipv6_ext_header(60, 0, {0, 0, 0, 0, 0, 0});
    }

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Malformed);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
}

TEST(ParserNetworkTest, IPv6TruncatedInsideExtHeader) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
           60, 64);

    b.u8(6);
    b.u8(1);
    b.bytes(4);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);

    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::IPv6);
}

TEST(ParserNetworkTest, TcpAllFlagsIndividually) {
    const uint8_t flags[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    for (uint8_t f : flags) {
        PacketBuilder b;
        b.ethernet(0x0800)
         .ipv4()
         .tcp(1000, 2000, f);

        const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
        EXPECT_EQ(p.status, ParseStatus::Ok);
        EXPECT_EQ(p.tcp_flags.value, f);
    }
}

TEST(ParserNetworkTest, TcpMalformedDataOffsetTooSmall) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4()
     .tcp(1234, 80, 0x02, 1000, 0, 4);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Malformed);
}

TEST(ParserNetworkTest, TcpTruncatedHeader) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6);
    b.bytes(10);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Truncated);
    EXPECT_EQ(p.network, NetworkProtocol::IPv4);
}

TEST(ParserNetworkTest, UdpValidWithPayload) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 17)
     .udp(53, 12345)
     .payload("0123456789");

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.transport, TransportProtocol::UDP);
    EXPECT_EQ(p.src_port, 53u);
    EXPECT_EQ(p.dst_port, 12345u);
    EXPECT_EQ(p.payload_offset, 14u + 20u + 8u);
    EXPECT_EQ(p.payload_length, 10u);
}

TEST(ParserNetworkTest, UdpMalformedLengthTooSmall) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 17)
     .udp(53, 53, 7);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Malformed);
}

TEST(ParserNetworkTest, IcmpEchoRequest) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 1)
     .icmp(8, 0);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.transport, TransportProtocol::ICMP);
    EXPECT_EQ(p.icmp_type, 8u);
    EXPECT_EQ(p.icmp_code, 0u);
    EXPECT_EQ(p.src_port, 0u);
    EXPECT_EQ(p.dst_port, 0u);
}

TEST(ParserNetworkTest, Icmpv6NeighborSolicitation) {
    PacketBuilder b;
    b.ethernet(0x86DD)
     .ipv6({0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
           58)
     .icmpv6(135, 0);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.transport, TransportProtocol::ICMPv6);
    EXPECT_EQ(p.icmp_type, 135u);
    EXPECT_EQ(p.icmp_code, 0u);
}

TEST(ParserNetworkTest, EthernetPaddingIgnoredInPayload) {
    PacketBuilder b;
    b.ethernet(0x0800)
     .ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 6, 64, 40)
     .tcp(80, 12345, 0x02, 1000, 0, 5)
     .bytes(6, 0);

    const ParsedPacket p = parse_packet(b.build(), LinkType::Ethernet);
    EXPECT_EQ(p.status, ParseStatus::Ok);
    EXPECT_EQ(p.transport, TransportProtocol::TCP);
    EXPECT_EQ(p.payload_length, 0u);
}

TEST(ParserNetworkTest, GoldenTcpdumpLoTcpAllTenPackets) {
    const auto pcap_path = std::filesystem::path(NETSIGHT_TEST_DATA_DIR) / "lo_tcp.pcap";
    std::string error;
    auto reader = PcapFileReader::open(pcap_path, error);
    ASSERT_NE(reader, nullptr) << error;
    const auto result = read_all(*reader);
    ASSERT_EQ(result.packets.size(), 10u);

    const ParsedPacket p0 = parse_packet(result.packets[0], LinkType::Ethernet);
    EXPECT_EQ(p0.status, ParseStatus::Ok);
    EXPECT_EQ(p0.network, NetworkProtocol::IPv4);
    EXPECT_EQ(p0.transport, TransportProtocol::TCP);
    EXPECT_EQ(p0.src_ip.to_string(), "127.0.0.1");
    EXPECT_EQ(p0.dst_ip.to_string(), "127.0.0.1");
    EXPECT_EQ(p0.src_port, 33626u);
    EXPECT_EQ(p0.dst_port, 8000u);
    EXPECT_TRUE(p0.tcp_flags.syn());
    EXPECT_FALSE(p0.tcp_flags.ack());

    const ParsedPacket p1 = parse_packet(result.packets[1], LinkType::Ethernet);
    EXPECT_EQ(p1.status, ParseStatus::Ok);
    EXPECT_EQ(p1.src_port, 8000u);
    EXPECT_EQ(p1.dst_port, 33626u);
    EXPECT_TRUE(p1.tcp_flags.syn());
    EXPECT_TRUE(p1.tcp_flags.ack());

    const ParsedPacket p2 = parse_packet(result.packets[2], LinkType::Ethernet);
    EXPECT_EQ(p2.status, ParseStatus::Ok);
    EXPECT_TRUE(p2.tcp_flags.ack());
    EXPECT_FALSE(p2.tcp_flags.syn());

    const ParsedPacket p9 = parse_packet(result.packets[9], LinkType::Ethernet);
    EXPECT_EQ(p9.status, ParseStatus::Ok);
    EXPECT_TRUE(p9.tcp_flags.fin());
    EXPECT_TRUE(p9.tcp_flags.ack());

    for (std::size_t i = 0; i < 10; ++i) {
        const ParsedPacket p = parse_packet(result.packets[i], LinkType::Ethernet);
        EXPECT_EQ(p.status, ParseStatus::Ok) << "Packet " << i << " failed parsing";
        EXPECT_EQ(p.network, NetworkProtocol::IPv4);
        EXPECT_EQ(p.transport, TransportProtocol::TCP);
        EXPECT_EQ(p.src_ip.to_string(), "127.0.0.1");
        EXPECT_EQ(p.dst_ip.to_string(), "127.0.0.1");
    }
}

TEST(ParserNetworkTest, EveryPrefixSafetyL3L4) {
    PacketBuilder b1;
    b1.ethernet(0x0800)
      .ipv4({192, 168, 1, 1}, {192, 168, 1, 2}, 6, 64, 0, 6)
      .ipv4_options({0x01, 0x01, 0x01, 0x00})
      .tcp(1234, 80, 0x02, 100, 0, 6)
      .tcp_options({0x02, 0x04, 0x05, 0xB4})
      .payload("HTTP GET /");

    PacketBuilder b2;
    b2.ethernet(0x86DD)
      .ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
            {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
            0)
      .ipv6_ext_header(17, 0, {0, 0, 0, 0, 0, 0})
      .udp(53, 53)
      .payload("DNS query bytes");

    PacketBuilder b3;
    b3.ethernet(0x0800)
      .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6, 64, 0, 5, 0x2000)
      .tcp(80, 8080)
      .payload("Fragment payload");

    auto verify_all_prefixes = [](const RawPacket& full_pkt, LinkType link) {
        for (std::size_t len = 0; len <= full_pkt.data.size(); ++len) {
            RawPacket prefix_pkt = full_pkt;
            prefix_pkt.data.resize(len);
            const ParsedPacket p = parse_packet(prefix_pkt, link);
            EXPECT_TRUE(p.status == ParseStatus::Ok ||
                        p.status == ParseStatus::Truncated ||
                        p.status == ParseStatus::Malformed)
                << "Unexpected status at prefix length " << len;
        }
    };

    verify_all_prefixes(b1.build(), LinkType::Ethernet);
    verify_all_prefixes(b2.build(), LinkType::Ethernet);
    verify_all_prefixes(b3.build(), LinkType::Ethernet);
}

TEST(ParserNetworkTest, StaticAsserts) {
    static_assert(std::is_trivially_copyable_v<ParsedPacket>);
    static_assert(std::is_trivially_copyable_v<IpAddress>);
    static_assert(std::is_trivially_copyable_v<TcpFlags>);
    EXPECT_TRUE(std::is_trivially_copyable_v<ParsedPacket>);
    EXPECT_TRUE(std::is_trivially_copyable_v<IpAddress>);
    EXPECT_TRUE(std::is_trivially_copyable_v<TcpFlags>);
}