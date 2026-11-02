#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "netsight/analytics/StatsAggregator.hpp"
#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "support/PacketBuilder.hpp"

using namespace netsight;
using namespace netsight::test;

TEST(StatsAggregatorTest, InitialSnapshotIsEmptyAndNonNull) {
    StatsAggregator agg{};
    const auto snap = agg.latest_snapshot();
    ASSERT_NE(snap, nullptr);
    EXPECT_EQ(snap->snapshot_seq, 0u);
    EXPECT_EQ(snap->total_packets, 0u);
    EXPECT_EQ(snap->total_wire_bytes, 0u);
    EXPECT_EQ(snap->total_captured_bytes, 0u);
    EXPECT_DOUBLE_EQ(snap->duration_seconds, 0.0);
    EXPECT_DOUBLE_EQ(snap->packets_per_second, 0.0);
    EXPECT_DOUBLE_EQ(snap->bytes_per_second, 0.0);
    EXPECT_TRUE(snap->top_talkers.empty());
    EXPECT_TRUE(snap->top_ports.empty());
    EXPECT_EQ(agg.tracked_talker_count(), 0u);
    EXPECT_EQ(agg.tracked_port_count(), 0u);
}

TEST(StatsAggregatorTest, CountsProtocolsAndBytesCorrectly) {
    StatsAggregator agg{};

    const auto raw_ipv4_tcp = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6).tcp(1000, 80).payload("tcp1").build();
    const auto raw_ipv4_udp = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 3}, 17).udp(2000, 53).payload("udp1").build();
    const auto raw_ipv4_icmp = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 4}, 1).icmp(8, 0).build();
    const auto raw_ipv6_tcp = PacketBuilder{}.ethernet(0x86DD).ipv6({0x20, 0x01}, {0x20, 0x02}, 6).tcp(3000, 443).build();
    const auto raw_ipv6_icmp = PacketBuilder{}.ethernet(0x86DD).ipv6({0x20, 0x01}, {0x20, 0x03}, 58).icmpv6(128, 0).build();
    const auto raw_arp = PacketBuilder{}.ethernet(0x0806).bytes(28, 0).build();
    const auto raw_vlan_tcp = PacketBuilder{}.ethernet(0x8100).vlan(100, 0x0800).ipv4({10, 0, 0, 5}, {10, 0, 0, 6}, 6).tcp(4000, 8080).build();
    const auto raw_frag = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 7}, {10, 0, 0, 8}, 6, 64, 0, 5, 64).payload("fragdata").build();

    const std::vector<RawPacket> packets = {
        raw_ipv4_tcp, raw_ipv4_udp, raw_ipv4_icmp,
        raw_ipv6_tcp, raw_ipv6_icmp, raw_arp,
        raw_vlan_tcp, raw_frag
    };

    uint64_t expected_wire_bytes = 0;
    for (const auto& raw : packets) {
        expected_wire_bytes += raw.original_length;
        agg.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = agg.publish();
    ASSERT_NE(snap, nullptr);
    EXPECT_EQ(snap->snapshot_seq, 1u);
    EXPECT_EQ(snap->total_packets, 8u);
    EXPECT_EQ(snap->total_wire_bytes, expected_wire_bytes);

    const auto sum_status = snap->status.ok + snap->status.truncated + snap->status.malformed + snap->status.unsupported_link;
    EXPECT_EQ(snap->total_packets, sum_status);
    EXPECT_EQ(snap->status.ok, 8u);

    const auto sum_l3 = snap->l3.ipv4.packets + snap->l3.ipv6.packets + snap->l3.arp.packets + snap->l3.other.packets;
    EXPECT_EQ(snap->status.ok, sum_l3);
    EXPECT_EQ(snap->l3.ipv4.packets, 5u);
    EXPECT_EQ(snap->l3.ipv6.packets, 2u);
    EXPECT_EQ(snap->l3.arp.packets, 1u);

    const auto sum_l4 = snap->l4.tcp.packets + snap->l4.udp.packets + snap->l4.icmp.packets + snap->l4.icmpv6.packets + snap->l4.other.packets + snap->l4.none.packets;
    EXPECT_EQ(snap->status.ok, sum_l4);
    EXPECT_EQ(snap->l4.tcp.packets, 3u);
    EXPECT_EQ(snap->l4.udp.packets, 1u);
    EXPECT_EQ(snap->l4.icmp.packets, 1u);
    EXPECT_EQ(snap->l4.icmpv6.packets, 1u);
    EXPECT_EQ(snap->l4.none.packets, 2u);

    EXPECT_EQ(snap->l3.vlan_tagged_packets, 1u);
    EXPECT_EQ(snap->l3.fragmented_packets, 1u);
}

TEST(StatsAggregatorTest, WireVsCapturedBytesOnTruncatedSnaplen) {
    StatsAggregator agg{};
    const auto full_raw = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 10}, {192, 168, 1, 20}, 6).tcp(5000, 80).payload("payload_data_here").build();
    const RawPacket truncated_raw(Timestamp{100}, full_raw.data.data(), 64, 1500);
    const auto parsed = parse_packet(truncated_raw, LinkType::Ethernet);
    ASSERT_EQ(parsed.status, ParseStatus::Ok);

    agg.record(parsed);
    const auto snap = agg.publish();

    EXPECT_EQ(snap->total_packets, 1u);
    EXPECT_EQ(snap->total_wire_bytes, 1500u);
    EXPECT_EQ(snap->total_captured_bytes, 64u);
    EXPECT_EQ(snap->l3.ipv4.bytes, 1500u);
    EXPECT_EQ(snap->l4.tcp.bytes, 1500u);
    ASSERT_EQ(snap->top_talkers.size(), 1u);
    EXPECT_EQ(snap->top_talkers[0].bytes, 1500u);
    ASSERT_EQ(snap->top_ports.size(), 1u);
    EXPECT_EQ(snap->top_ports[0].bytes, 1500u);
}

TEST(StatsAggregatorTest, MalformedAndTruncatedExcludedFromProtocolAndTopTables) {
    StatsAggregator agg{};
    const auto valid_raw = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6).tcp(1234, 80).build();
    const auto valid_parsed = parse_packet(valid_raw, LinkType::Ethernet);

    const RawPacket trunc_raw(Timestamp{0}, valid_raw.data.data(), 10, 100);
    const auto trunc_parsed = parse_packet(trunc_raw, LinkType::Ethernet);
    EXPECT_EQ(trunc_parsed.status, ParseStatus::Truncated);

    const auto malformed_raw = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6, 64, 0, 3).build();
    const auto malformed_parsed = parse_packet(malformed_raw, LinkType::Ethernet);
    EXPECT_EQ(malformed_parsed.status, ParseStatus::Malformed);

    const auto unsupported_parsed = parse_packet(valid_raw, LinkType::Unknown);
    EXPECT_EQ(unsupported_parsed.status, ParseStatus::UnsupportedLinkType);

    agg.record(valid_parsed);
    agg.record(trunc_parsed);
    agg.record(malformed_parsed);
    agg.record(unsupported_parsed);

    const auto snap = agg.publish();
    EXPECT_EQ(snap->total_packets, 4u);
    EXPECT_EQ(snap->status.ok, 1u);
    EXPECT_EQ(snap->status.truncated, 1u);
    EXPECT_EQ(snap->status.malformed, 1u);
    EXPECT_EQ(snap->status.unsupported_link, 1u);

    EXPECT_EQ(snap->l3.ipv4.packets, 1u);
    EXPECT_EQ(snap->l4.tcp.packets, 1u);
    EXPECT_EQ(snap->top_talkers.size(), 1u);
    EXPECT_EQ(snap->top_ports.size(), 1u);
}

TEST(StatsAggregatorTest, ArpDoesNotPolluteTalkersOrPorts) {
    StatsAggregator agg{};
    const auto arp_raw = PacketBuilder{}.ethernet(0x0806).bytes(28, 0).build();
    const auto arp_parsed = parse_packet(arp_raw, LinkType::Ethernet);

    for (int i = 0; i < 10; ++i) {
        agg.record(arp_parsed);
    }

    const auto snap = agg.publish();
    EXPECT_EQ(snap->total_packets, 10u);
    EXPECT_EQ(snap->status.ok, 10u);
    EXPECT_EQ(snap->l3.arp.packets, 10u);
    EXPECT_EQ(snap->l4.none.packets, 10u);
    EXPECT_TRUE(snap->top_talkers.empty());
    EXPECT_TRUE(snap->top_ports.empty());
}

TEST(StatsAggregatorTest, DurationAndRatesFromPacketTimestamps) {
    StatsAggregator agg{};
    const auto base_raw = PacketBuilder{}.ethernet(0x0800).ipv4().tcp().build();

    const RawPacket raw1(Timestamp(1'000'000), base_raw.data.data(), base_raw.data.size(), 1000);
    const RawPacket raw2(Timestamp(3'000'000), base_raw.data.data(), base_raw.data.size(), 1000);
    const RawPacket raw3(Timestamp(2'000'000), base_raw.data.data(), base_raw.data.size(), 1000);

    agg.record(parse_packet(raw1, LinkType::Ethernet));
    agg.record(parse_packet(raw2, LinkType::Ethernet));
    agg.record(parse_packet(raw3, LinkType::Ethernet));

    const auto snap = agg.publish();
    EXPECT_EQ(snap->first_packet_ts, Timestamp(1'000'000));
    EXPECT_EQ(snap->last_packet_ts, Timestamp(3'000'000));
    EXPECT_DOUBLE_EQ(snap->duration_seconds, 2.0);
    EXPECT_DOUBLE_EQ(snap->packets_per_second, 1.5);
    EXPECT_DOUBLE_EQ(snap->bytes_per_second, 1500.0);
}

TEST(StatsAggregatorTest, SinglePacketOrZeroDurationGivesZeroRates) {
    {
        StatsAggregator agg{};
        const auto raw = PacketBuilder{}.ethernet(0x0800).ipv4().tcp().build(Timestamp(500'000));
        agg.record(parse_packet(raw, LinkType::Ethernet));

        const auto snap = agg.publish();
        EXPECT_DOUBLE_EQ(snap->duration_seconds, 0.0);
        EXPECT_DOUBLE_EQ(snap->packets_per_second, 0.0);
        EXPECT_DOUBLE_EQ(snap->bytes_per_second, 0.0);
    }
    {
        StatsAggregator agg{};
        const auto raw = PacketBuilder{}.ethernet(0x0800).ipv4().tcp().build(Timestamp(500'000));
        agg.record(parse_packet(raw, LinkType::Ethernet));
        agg.record(parse_packet(raw, LinkType::Ethernet));

        const auto snap = agg.publish();
        EXPECT_DOUBLE_EQ(snap->duration_seconds, 0.0);
        EXPECT_DOUBLE_EQ(snap->packets_per_second, 0.0);
        EXPECT_DOUBLE_EQ(snap->bytes_per_second, 0.0);
    }
}

TEST(StatsAggregatorTest, TopTalkersOrderingAndTieBreaking) {
    StatsConfig cfg{};
    cfg.top_n = 4;
    StatsAggregator agg{cfg};

    const auto ip_a = parse_ip_address("10.0.0.1").value();
    const auto ip_b = parse_ip_address("10.0.0.2").value();
    const auto ip_c = parse_ip_address("10.0.0.3").value();
    const auto ip_d = parse_ip_address("10.0.0.4").value();
    const auto ip_e = parse_ip_address("10.0.0.5").value();

    auto send = [&](const IpAddress& ip, uint64_t wire_bytes, int count) {
        for (int i = 0; i < count; ++i) {
            ParsedPacket pkt{};
            pkt.status = ParseStatus::Ok;
            pkt.network = NetworkProtocol::IPv4;
            pkt.src_ip = ip;
            pkt.wire_length = static_cast<uint32_t>(wire_bytes / count);
            agg.record(pkt);
        }
    };

    send(ip_a, 1000, 1);
    send(ip_b, 3000, 3);
    send(ip_c, 2000, 2);
    send(ip_d, 2000, 2);
    send(ip_e, 2000, 5);

    const auto snap = agg.publish();
    ASSERT_EQ(snap->top_talkers.size(), 4u);

    EXPECT_EQ(snap->top_talkers[0].ip, ip_b);
    EXPECT_EQ(snap->top_talkers[0].bytes, 3000u);

    EXPECT_EQ(snap->top_talkers[1].ip, ip_e);
    EXPECT_EQ(snap->top_talkers[1].packets, 5u);

    EXPECT_EQ(snap->top_talkers[2].ip, ip_c);
    EXPECT_EQ(snap->top_talkers[3].ip, ip_d);
}

TEST(StatsAggregatorTest, TopPortsTracksTcpAndUdpDstPortWithTieBreaking) {
    StatsConfig cfg{};
    cfg.top_n = 3;
    StatsAggregator agg{cfg};

    auto send_port = [&](TransportProtocol proto, uint16_t dst_p, uint64_t wire_bytes, int count) {
        for (int i = 0; i < count; ++i) {
            ParsedPacket pkt{};
            pkt.status = ParseStatus::Ok;
            pkt.transport = proto;
            pkt.dst_port = dst_p;
            pkt.wire_length = static_cast<uint32_t>(wire_bytes / count);
            agg.record(pkt);
        }
    };

    send_port(TransportProtocol::TCP, 443, 500, 1);
    send_port(TransportProtocol::UDP, 53, 1000, 2);
    send_port(TransportProtocol::TCP, 80, 1000, 2);
    send_port(TransportProtocol::ICMP, 999, 10000, 10);

    const auto snap = agg.publish();
    ASSERT_EQ(snap->top_ports.size(), 3u);

    EXPECT_EQ(snap->top_ports[0].port, 53u);
    EXPECT_EQ(snap->top_ports[1].port, 80u);
    EXPECT_EQ(snap->top_ports[2].port, 443u);
}

TEST(StatsAggregatorTest, BoundedTalkersAndPortsEnforceCapAndCountUntracked) {
    StatsConfig cfg{};
    cfg.max_tracked_talkers = 3;
    cfg.max_tracked_ports = 2;
    StatsAggregator agg{cfg};

    for (uint8_t i = 1; i <= 5; ++i) {
        const auto ip = parse_ip_address("10.0.0." + std::to_string(i)).value();
        const uint16_t port = static_cast<uint16_t>(8000 + (i % 4));

        for (int p = 0; p < 2; ++p) {
            ParsedPacket pkt{};
            pkt.status = ParseStatus::Ok;
            pkt.network = NetworkProtocol::IPv4;
            pkt.src_ip = ip;
            pkt.transport = TransportProtocol::TCP;
            pkt.dst_port = port;
            pkt.wire_length = 100;
            agg.record(pkt);
        }
    }

    EXPECT_EQ(agg.tracked_talker_count(), 3u);
    EXPECT_EQ(agg.tracked_port_count(), 2u);

    const auto snap = agg.publish();
    EXPECT_EQ(snap->drops.untracked_talker_packets, 4u);
    EXPECT_GT(snap->drops.untracked_port_packets, 0u);

    const auto tracked_ip = snap->top_talkers[0].ip;
    const auto before_bytes = snap->top_talkers[0].bytes;
    ParsedPacket extra_pkt{};
    extra_pkt.status = ParseStatus::Ok;
    extra_pkt.src_ip = tracked_ip;
    extra_pkt.wire_length = 50;
    agg.record(extra_pkt);

    const auto snap2 = agg.publish();
    EXPECT_EQ(agg.tracked_talker_count(), 3u);
    EXPECT_EQ(snap2->drops.untracked_talker_packets, 4u);
    EXPECT_EQ(snap2->top_talkers[0].bytes, before_bytes + 50);
}

TEST(StatsAggregatorTest, ExternalDropsMergedWithInternalUntracked) {
    StatsConfig cfg{};
    cfg.max_tracked_talkers = 1;
    StatsAggregator agg{cfg};

    ParsedPacket pkt1{};
    pkt1.status = ParseStatus::Ok;
    pkt1.src_ip = parse_ip_address("10.0.0.1").value();
    pkt1.wire_length = 100;
    agg.record(pkt1);

    ParsedPacket pkt2{};
    pkt2.status = ParseStatus::Ok;
    pkt2.src_ip = parse_ip_address("10.0.0.2").value();
    pkt2.wire_length = 100;
    for (int i = 0; i < 5; ++i) {
        agg.record(pkt2);
    }

    DropCounters ext_drops{};
    ext_drops.filtered_out = 7;
    ext_drops.queue_dropped = 3;
    ext_drops.kernel_dropped = 11;
    ext_drops.interface_dropped = 2;

    const auto snap = agg.publish(ext_drops);
    EXPECT_EQ(snap->drops.filtered_out, 7u);
    EXPECT_EQ(snap->drops.queue_dropped, 3u);
    EXPECT_EQ(snap->drops.kernel_dropped, 11u);
    EXPECT_EQ(snap->drops.interface_dropped, 2u);
    EXPECT_EQ(snap->drops.untracked_talker_packets, 5u);
    EXPECT_EQ(snap->snapshot_seq, 1u);
}

TEST(StatsAggregatorTest, ResetClearsAllStateAndPublishedSnapshot) {
    StatsAggregator agg{};
    ParsedPacket pkt{};
    pkt.status = ParseStatus::Ok;
    pkt.network = NetworkProtocol::IPv4;
    pkt.src_ip = parse_ip_address("10.0.0.1").value();
    pkt.transport = TransportProtocol::TCP;
    pkt.dst_port = 80;
    pkt.wire_length = 100;
    agg.record(pkt);

    agg.publish();
    EXPECT_GT(agg.latest_snapshot()->total_packets, 0u);
    EXPECT_EQ(agg.latest_snapshot()->snapshot_seq, 1u);
    EXPECT_EQ(agg.tracked_talker_count(), 1u);

    agg.reset();

    EXPECT_EQ(agg.tracked_talker_count(), 0u);
    EXPECT_EQ(agg.tracked_port_count(), 0u);
    const auto snap = agg.latest_snapshot();
    EXPECT_EQ(snap->total_packets, 0u);
    EXPECT_EQ(snap->snapshot_seq, 0u);
    EXPECT_TRUE(snap->top_talkers.empty());
}

TEST(StatsAggregatorTest, ConcurrentPublishAndLatestSnapshotAreThreadSafe) {
    StatsAggregator agg{};
    std::atomic<bool> stop{false};

    std::thread writer([&]() {
        for (uint64_t i = 1; i <= 500; ++i) {
            ParsedPacket pkt{};
            pkt.status = ParseStatus::Ok;
            pkt.network = NetworkProtocol::IPv4;
            pkt.src_ip = parse_ip_address("10.0.0." + std::to_string(1 + (i % 50))).value();
            pkt.transport = TransportProtocol::TCP;
            pkt.dst_port = static_cast<uint16_t>(80 + (i % 10));
            pkt.wire_length = 100;
            agg.record(pkt);

            if (i % 5 == 0) {
                agg.publish();
            }
        }
        agg.publish();
        stop.store(true);
    });

    std::vector<std::thread> readers;
    readers.reserve(4);
    for (int r = 0; r < 4; ++r) {
        readers.emplace_back([&]() {
            while (!stop.load()) {
                const auto snap = agg.latest_snapshot();
                ASSERT_NE(snap, nullptr);
                const auto sum_status = snap->status.ok + snap->status.truncated +
                                       snap->status.malformed + snap->status.unsupported_link;
                EXPECT_EQ(snap->total_packets, sum_status);
            }
        });
    }

    writer.join();
    for (auto& reader : readers) {
        reader.join();
    }

    const auto final_snap = agg.latest_snapshot();
    EXPECT_EQ(final_snap->total_packets, 500u);
    EXPECT_GE(final_snap->snapshot_seq, 100u);
}