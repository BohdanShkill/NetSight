#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <vector>

#include "netsight/analytics/Alert.hpp"
#include "netsight/analytics/SlidingWindow.hpp"
#include "netsight/analytics/SynFloodDetector.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "support/PacketBuilder.hpp"

using namespace netsight;
using namespace netsight::test;

TEST(SynFloodDetectorTest, SlidingWindowAccumulatesAndExpiresBuckets) {
    SlidingWindow<10> window{Timestamp{1'000'000}};
    EXPECT_EQ(window.bucket_duration(), Timestamp{100'000});
    EXPECT_EQ(window.window_duration(), Timestamp{1'000'000});

    window.add(Timestamp{0}, 5);
    window.add(Timestamp{100'000}, 5);
    window.add(Timestamp{500'000}, 5);
    window.add(Timestamp{900'000}, 5);

    EXPECT_EQ(window.total(), 20u);

    window.advance(Timestamp{1'000'000});
    EXPECT_EQ(window.total(), 15u);

    window.advance(Timestamp{1'100'000});
    EXPECT_EQ(window.total(), 10u);

    window.advance(Timestamp{2'500'000});
    EXPECT_EQ(window.total(), 0u);
}

TEST(SynFloodDetectorTest, SlidingWindowHandlesOutOfOrderPacketsSafely) {
    SlidingWindow<10> window{Timestamp{1'000'000}};

    window.add(Timestamp{500'000}, 1);
    EXPECT_EQ(window.total(), 1u);

    window.add(Timestamp{300'000}, 2);
    EXPECT_EQ(window.total(), 3u);

    window.add(Timestamp{1'600'000}, 4);
    EXPECT_EQ(window.total(), 4u);

    window.add(Timestamp{200'000}, 5);
    EXPECT_EQ(window.total(), 4u);
}

TEST(SynFloodDetectorTest, BelowThresholdTrafficProducesNoAlert) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 50;
    SynFloodDetector detector{cfg};

    for (int i = 0; i < 49; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{i * 10'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    EXPECT_TRUE(detector.alerts().empty());
    EXPECT_TRUE(detector.active_alerts().empty());
    EXPECT_EQ(detector.tracked_target_count(), 1u);
}

TEST(SynFloodDetectorTest, SpoofedTenThousandSynsTriggerSingleVictimAlert) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 100;
    SynFloodDetector detector{cfg};

    for (uint32_t i = 1; i <= 10'000; ++i) {
        const uint8_t b1 = 100;
        const uint8_t b2 = static_cast<uint8_t>((i >> 16) & 0xFF);
        const uint8_t b3 = static_cast<uint8_t>((i >> 8) & 0xFF);
        const uint8_t b4 = static_cast<uint8_t>(i & 0xFF);

        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({b1, b2, b3, b4}, {10, 0, 0, 1}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + (i % 50000)), 443, 0x02)
                                        .build(Timestamp{static_cast<int64_t>((i - 1) * 100)});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    EXPECT_EQ(detector.tracked_target_count(), 1u);

    const auto& alerts = detector.alerts();
    ASSERT_EQ(alerts.size(), 1u);
    const auto& alert = alerts.front();
    EXPECT_EQ(alert.id, 1u);
    EXPECT_EQ(alert.type, AlertType::SynFlood);
    EXPECT_EQ(alert.state, AlertState::Active);
    EXPECT_EQ(alert.dst_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{10, 0, 0, 1}.data()));
    EXPECT_EQ(alert.dst_port, 443u);
    EXPECT_EQ(alert.syn_count, 10'000u);
    EXPECT_EQ(alert.syn_ack_count, 0u);
    EXPECT_DOUBLE_EQ(alert.peak_rate_pps, 10'000.0);
}

TEST(SynFloodDetectorTest, BalancedSynAndSynAckDoesNotTriggerFalsePositive) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 50;
    cfg.max_syn_ack_ratio = 0.25;
    SynFloodDetector detector{cfg};

    for (int i = 0; i < 100; ++i) {
        const auto raw_syn = PacketBuilder{}.ethernet(0x0800)
                                            .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                            .tcp(static_cast<uint16_t>(20000 + i), 443, 0x02)
                                            .build(Timestamp{i * 5'000});
        detector.record(parse_packet(raw_syn, LinkType::Ethernet));

        if (i < 80) {
            const auto raw_syn_ack = PacketBuilder{}.ethernet(0x0800)
                                                    .ipv4({192, 168, 1, 10}, {10, 0, 0, 1}, 6)
                                                    .tcp(443, static_cast<uint16_t>(20000 + i), 0x12)
                                                    .build(Timestamp{i * 5'000 + 100});
            detector.record(parse_packet(raw_syn_ack, LinkType::Ethernet));
        }
    }

    EXPECT_TRUE(detector.alerts().empty());
}

TEST(SynFloodDetectorTest, StraySynAcksDoNotAllocateTargets) {
    SynFloodDetector detector{};

    for (int i = 0; i < 500; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 2}, {192, 168, 1, 1}, 6)
                                        .tcp(static_cast<uint16_t>(1000 + i), 50000, 0x12)
                                        .build(Timestamp{i * 1000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    EXPECT_EQ(detector.tracked_target_count(), 0u);
    EXPECT_TRUE(detector.alerts().empty());
}

TEST(SynFloodDetectorTest, HysteresisPreventsFlappingAndResolvesOnCooldown) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 100;
    cfg.recovery_syn_threshold = 30;
    cfg.window_duration = Timestamp{1'000'000};
    SynFloodDetector detector{cfg};

    for (int i = 0; i < 100; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{i * 5'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }
    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    const auto raw_check = PacketBuilder{}.ethernet(0x0800)
                                          .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                          .tcp(20000, 80, 0x02)
                                          .build(Timestamp{1'100'000});
    detector.record(parse_packet(raw_check, LinkType::Ethernet));
    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    detector.on_tick(Timestamp{1'600'000});
    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Resolved);
    EXPECT_EQ(detector.alerts().front().ended_at, Timestamp{1'600'000});
}

TEST(SynFloodDetectorTest, BoundedTableDropsNewTargetsWhenFull) {
    SynFloodConfig cfg{};
    cfg.max_tracked_targets = 3;
    cfg.entry_ttl = Timestamp{5'000'000};
    SynFloodDetector detector{cfg};

    for (uint16_t port = 80; port < 83; ++port) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(10000, port, 0x02)
                                        .build(Timestamp{1'000'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }
    EXPECT_EQ(detector.tracked_target_count(), 3u);
    EXPECT_EQ(detector.untracked_target_packets(), 0u);

    const auto raw4 = PacketBuilder{}.ethernet(0x0800)
                                     .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                     .tcp(10000, 84, 0x02)
                                     .build(Timestamp{2'000'000});
    detector.record(parse_packet(raw4, LinkType::Ethernet));
    EXPECT_EQ(detector.tracked_target_count(), 3u);
    EXPECT_EQ(detector.untracked_target_packets(), 1u);

    const auto raw5 = PacketBuilder{}.ethernet(0x0800)
                                     .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                     .tcp(10000, 85, 0x02)
                                     .build(Timestamp{7'000'000});
    detector.record(parse_packet(raw5, LinkType::Ethernet));
    EXPECT_EQ(detector.tracked_target_count(), 1u);
}

TEST(SynFloodDetectorTest, TtlEvictionRemovesStaleTargets) {
    SynFloodConfig cfg{};
    cfg.entry_ttl = Timestamp{5'000'000};
    SynFloodDetector detector{cfg};

    const auto raw1 = PacketBuilder{}.ethernet(0x0800)
                                     .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                     .tcp(10000, 80, 0x02)
                                     .build(Timestamp{1'000'000});
    detector.record(parse_packet(raw1, LinkType::Ethernet));

    const auto raw2 = PacketBuilder{}.ethernet(0x0800)
                                     .ipv4({10, 0, 0, 1}, {192, 168, 1, 20}, 6)
                                     .tcp(10000, 80, 0x02)
                                     .build(Timestamp{3'000'000});
    detector.record(parse_packet(raw2, LinkType::Ethernet));

    EXPECT_EQ(detector.tracked_target_count(), 2u);

    detector.on_tick(Timestamp{7'000'000});
    EXPECT_EQ(detector.tracked_target_count(), 1u);

    detector.on_tick(Timestamp{9'000'000});
    EXPECT_EQ(detector.tracked_target_count(), 0u);
}

TEST(SynFloodDetectorTest, TtlEvictionClosesActiveAlert) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 10;
    cfg.entry_ttl = Timestamp{5'000'000};
    SynFloodDetector detector{cfg};

    for (int i = 0; i < 15; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{i * 10'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    detector.on_tick(Timestamp{6'000'000});

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Resolved);
    EXPECT_EQ(detector.alerts().front().ended_at, Timestamp{6'000'000});
    EXPECT_EQ(detector.tracked_target_count(), 0u);
}

TEST(SynFloodDetectorTest, AlertHistoryBoundedByMaxAlerts) {
    SynFloodConfig cfg{};
    cfg.max_alerts = 3;
    cfg.syn_threshold = 5;
    cfg.recovery_syn_threshold = 1;
    SynFloodDetector detector{cfg};

    for (uint64_t wave = 0; wave < 5; ++wave) {
        const int64_t start_us = static_cast<int64_t>(wave * 10'000'000);
        for (int i = 0; i < 6; ++i) {
            const auto raw = PacketBuilder{}.ethernet(0x0800)
                                            .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                            .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                            .build(Timestamp{start_us + i * 1'000});
            detector.record(parse_packet(raw, LinkType::Ethernet));
        }
        detector.on_tick(Timestamp{start_us + 2'000'000});
    }

    const auto& alerts = detector.alerts();
    ASSERT_EQ(alerts.size(), 3u);
    EXPECT_EQ(alerts[0].id, 3u);
    EXPECT_EQ(alerts[1].id, 4u);
    EXPECT_EQ(alerts[2].id, 5u);
}

TEST(SynFloodDetectorTest, NonTcpRstAndMalformedPacketsIgnored) {
    SynFloodDetector detector{};

    for (int i = 0; i < 200; ++i) {
        const auto raw_udp = PacketBuilder{}.ethernet(0x0800)
                                            .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 17)
                                            .udp(10000, 80)
                                            .build(Timestamp{i * 1000});
        detector.record(parse_packet(raw_udp, LinkType::Ethernet));

        const auto raw_icmp = PacketBuilder{}.ethernet(0x0800)
                                             .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 1)
                                             .icmp(8, 0)
                                             .build(Timestamp{i * 1000});
        detector.record(parse_packet(raw_icmp, LinkType::Ethernet));

        const auto raw_ack = PacketBuilder{}.ethernet(0x0800)
                                            .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                            .tcp(10000, 80, 0x10)
                                            .build(Timestamp{i * 1000});
        detector.record(parse_packet(raw_ack, LinkType::Ethernet));

        const auto raw_syn_rst = PacketBuilder{}.ethernet(0x0800)
                                                .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                                .tcp(10000, 80, 0x06)
                                                .build(Timestamp{i * 1000});
        detector.record(parse_packet(raw_syn_rst, LinkType::Ethernet));
    }

    ParsedPacket malformed_pkt{};
    malformed_pkt.status = ParseStatus::Malformed;
    malformed_pkt.transport = TransportProtocol::TCP;
    detector.record(malformed_pkt);

    EXPECT_EQ(detector.tracked_target_count(), 0u);
    EXPECT_TRUE(detector.alerts().empty());
}

TEST(SynFloodDetectorTest, ResetClearsTargetsAlertsAndCounters) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 10;
    SynFloodDetector detector{cfg};

    for (int i = 0; i < 20; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{i * 1'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    EXPECT_GT(detector.tracked_target_count(), 0u);
    EXPECT_FALSE(detector.alerts().empty());

    detector.reset();

    EXPECT_EQ(detector.tracked_target_count(), 0u);
    EXPECT_TRUE(detector.alerts().empty());
    EXPECT_TRUE(detector.active_alerts().empty());
    EXPECT_EQ(detector.untracked_target_packets(), 0u);
}

TEST(SynFloodDetectorTest, EvictedActiveAlertDoesNotWedgeTarget) {
    SynFloodConfig cfg{};
    cfg.syn_threshold = 10;
    cfg.recovery_syn_threshold = 3;
    cfg.max_alerts = 1;
    SynFloodDetector detector{cfg};

    for (int i = 0; i < 15; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{1'000 + i * 1'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().id, 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    for (int i = 0; i < 15; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 20}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{20'000 + i * 1'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().id, 2u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    detector.on_tick(Timestamp{3'000'000});

    for (int i = 0; i < 15; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(20000 + i), 80, 0x02)
                                        .build(Timestamp{4'000'000 + i * 1'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().id, 3u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);
    EXPECT_EQ(detector.alerts().front().dst_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{192, 168, 1, 10}.data()));
}

TEST(SynFloodDetectorTest, TopTargetsReturnsSortedActiveCandidatesAndRespectsLimit) {
    SynFloodDetector detector{};

    for (int i = 0; i < 50; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{100'000 + i * 1'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    for (int i = 0; i < 20; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 2}, {192, 168, 1, 20}, 6)
                                        .tcp(static_cast<uint16_t>(20000 + i), 443, 0x02)
                                        .build(Timestamp{100'000 + i * 1'000});
        detector.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto targets = detector.top_targets(10);
    ASSERT_EQ(targets.size(), 2u);
    EXPECT_EQ(targets[0].dst_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{192, 168, 1, 10}.data()));
    EXPECT_EQ(targets[0].dst_port, 80);
    EXPECT_EQ(targets[0].syn_count, 50u);
    EXPECT_EQ(targets[1].dst_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{192, 168, 1, 20}.data()));
    EXPECT_EQ(targets[1].dst_port, 443);
    EXPECT_EQ(targets[1].syn_count, 20u);

    const auto limited = detector.top_targets(1);
    ASSERT_EQ(limited.size(), 1u);
    EXPECT_EQ(limited[0].dst_port, 80);
}