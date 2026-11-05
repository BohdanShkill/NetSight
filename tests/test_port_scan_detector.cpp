#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <vector>

#include "netsight/analytics/Alert.hpp"
#include "netsight/analytics/PortScanDetector.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "support/PacketBuilder.hpp"

using namespace netsight;
using namespace netsight::test;

namespace {

ParsedPacket make_tcp_packet(const std::array<uint8_t, 4>& src,
                             const std::array<uint8_t, 4>& dst,
                             uint16_t sport,
                             uint16_t dport,
                             uint8_t flags,
                             Timestamp ts) {
    const auto raw = PacketBuilder{}.ethernet(0x0800)
                                    .ipv4(src, dst, 6)
                                    .tcp(sport, dport, flags)
                                    .build(ts);
    return parse_packet(raw, LinkType::Ethernet);
}

}

TEST(PortScanDetectorTest, BelowThresholdDistinctPortsNoAlert) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 19; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{p * 10'000}));
    }

    EXPECT_TRUE(detector.alerts().empty());
    EXPECT_TRUE(detector.active_alerts().empty());
    EXPECT_EQ(detector.tracked_source_count(), 1u);
}

TEST(PortScanDetectorTest, VerticalSynScanTriggersSingleAlert) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 1024; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{static_cast<int64_t>(p * 1'000)}));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    const auto& alert = detector.alerts().front();
    EXPECT_EQ(alert.id, 1u);
    EXPECT_EQ(alert.type, AlertType::PortScan);
    EXPECT_EQ(alert.state, AlertState::Active);
    EXPECT_EQ(alert.src_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{10, 0, 0, 66}.data()));
    EXPECT_EQ(alert.dst_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{10, 0, 0, 1}.data()));
    EXPECT_EQ(alert.dst_port, 0u);
    EXPECT_EQ(alert.started_at, Timestamp{20 * 1'000});
    EXPECT_EQ(alert.unique_ports, 64u);
    EXPECT_EQ(detector.active_alerts().size(), 1u);
}

TEST(PortScanDetectorTest, RetransmittedSynToSamePortCountedOnce) {
    PortScanDetector detector{};

    for (int i = 0; i < 500; ++i) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, 80, 0x02, Timestamp{i * 4'000}));
    }

    EXPECT_TRUE(detector.alerts().empty());
    EXPECT_EQ(detector.tracked_source_count(), 1u);
}

TEST(PortScanDetectorTest, StealthFinNullXmasScansDetected) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 25; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 10}, {192, 168, 1, 1}, 10000, p, 0x01, Timestamp{p * 1'000}));
        detector.record(make_tcp_packet({10, 0, 0, 20}, {192, 168, 1, 1}, 10000, p, 0x00, Timestamp{p * 1'000 + 100}));
        detector.record(make_tcp_packet({10, 0, 0, 30}, {192, 168, 1, 1}, 10000, p, 0x29, Timestamp{p * 1'000 + 200}));
    }

    ASSERT_EQ(detector.alerts().size(), 3u);
    EXPECT_EQ(detector.active_alerts().size(), 3u);

    EXPECT_EQ(detector.alerts()[0].src_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{10, 0, 0, 10}.data()));
    EXPECT_EQ(detector.alerts()[1].src_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{10, 0, 0, 20}.data()));
    EXPECT_EQ(detector.alerts()[2].src_ip, IpAddress::from_ipv4(std::array<uint8_t, 4>{10, 0, 0, 30}.data()));
}

TEST(PortScanDetectorTest, RepliesAckAndRstAreNotProbes) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 50; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 1}, {10, 0, 0, 2}, 80, p, 0x12, Timestamp{p * 1'000}));
        detector.record(make_tcp_packet({10, 0, 0, 1}, {10, 0, 0, 2}, 80, p, 0x14, Timestamp{p * 1'000 + 100}));
        detector.record(make_tcp_packet({10, 0, 0, 1}, {10, 0, 0, 2}, 80, p, 0x10, Timestamp{p * 1'000 + 200}));
        detector.record(make_tcp_packet({10, 0, 0, 1}, {10, 0, 0, 2}, 80, p, 0x04, Timestamp{p * 1'000 + 300}));
        detector.record(make_tcp_packet({10, 0, 0, 1}, {10, 0, 0, 2}, 80, p, 0x06, Timestamp{p * 1'000 + 400}));

        const auto raw_udp = PacketBuilder{}.ethernet(0x0800)
                                            .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 17)
                                            .udp(10000, p)
                                            .build(Timestamp{p * 1'000 + 500});
        detector.record(parse_packet(raw_udp, LinkType::Ethernet));
    }

    ParsedPacket malformed_pkt{};
    malformed_pkt.status = ParseStatus::Malformed;
    malformed_pkt.transport = TransportProtocol::TCP;
    detector.record(malformed_pkt);

    EXPECT_EQ(detector.tracked_source_count(), 0u);
    EXPECT_TRUE(detector.alerts().empty());
}

TEST(PortScanDetectorTest, SlowScanOutsideWindowNotDetected) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 100; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{static_cast<int64_t>(p * 300'000)}));
    }

    EXPECT_TRUE(detector.alerts().empty());
    EXPECT_EQ(detector.tracked_source_count(), 1u);
}

TEST(PortScanDetectorTest, HysteresisResolvesAfterScanStops) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 30; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{static_cast<int64_t>(p * 30'000)}));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    const Timestamp last_ts{30 * 30'000};
    detector.on_tick(Timestamp{last_ts.count() + 5'000'000});

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Resolved);
    EXPECT_EQ(detector.alerts().front().ended_at, Timestamp{last_ts.count() + 5'000'000});
    EXPECT_TRUE(detector.active_alerts().empty());
}

TEST(PortScanDetectorTest, SpoofedSourcesBoundedByMaxTrackedSources) {
    PortScanConfig cfg{};
    cfg.max_tracked_sources = 100;
    PortScanDetector detector{cfg};

    for (uint32_t i = 1; i <= 1000; ++i) {
        const uint8_t b2 = static_cast<uint8_t>((i >> 8) & 0xFF);
        const uint8_t b3 = static_cast<uint8_t>(i & 0xFF);
        detector.record(make_tcp_packet({10, b2, b3, 1}, {192, 168, 1, 10}, 10000, 80, 0x02, Timestamp{static_cast<int64_t>(i * 500)}));
    }

    EXPECT_EQ(detector.tracked_source_count(), 100u);
    EXPECT_EQ(detector.untracked_source_packets(), 900u);
    EXPECT_TRUE(detector.alerts().empty());
}

TEST(PortScanDetectorTest, TtlEvictionFreesSlotsForNewSources) {
    PortScanConfig cfg{};
    cfg.max_tracked_sources = 2;
    cfg.entry_ttl = Timestamp{10'000'000};
    PortScanDetector detector{cfg};

    detector.record(make_tcp_packet({10, 0, 0, 1}, {192, 168, 1, 10}, 10000, 80, 0x02, Timestamp{1'000'000}));
    detector.record(make_tcp_packet({10, 0, 0, 2}, {192, 168, 1, 10}, 10000, 80, 0x02, Timestamp{1'000'000}));
    EXPECT_EQ(detector.tracked_source_count(), 2u);

    detector.record(make_tcp_packet({10, 0, 0, 3}, {192, 168, 1, 10}, 10000, 80, 0x02, Timestamp{2'000'000}));
    EXPECT_EQ(detector.tracked_source_count(), 2u);
    EXPECT_EQ(detector.untracked_source_packets(), 1u);

    detector.record(make_tcp_packet({10, 0, 0, 4}, {192, 168, 1, 10}, 10000, 80, 0x02, Timestamp{12'000'000}));
    EXPECT_EQ(detector.tracked_source_count(), 1u);
    EXPECT_EQ(detector.untracked_source_packets(), 1u);
}

TEST(PortScanDetectorTest, AlertHistoryBoundedAndIdsMonotonic) {
    PortScanConfig cfg{};
    cfg.max_alerts = 3;
    cfg.port_threshold = 20;
    cfg.window_duration = Timestamp{5'000'000};
    PortScanDetector detector{cfg};

    for (uint64_t wave = 0; wave < 5; ++wave) {
        const int64_t base_ts = static_cast<int64_t>(wave * 20'000'000);
        for (uint16_t p = 1; p <= 25; ++p) {
            detector.record(make_tcp_packet({10, 0, 0, static_cast<uint8_t>(wave + 1)},
                                            {192, 168, 1, 10},
                                            10000,
                                            p,
                                            0x02,
                                            Timestamp{base_ts + p * 10'000}));
        }
        detector.on_tick(Timestamp{base_ts + 10'000'000});
    }

    const auto& alerts = detector.alerts();
    ASSERT_EQ(alerts.size(), 3u);
    EXPECT_EQ(alerts[0].id, 3u);
    EXPECT_EQ(alerts[1].id, 4u);
    EXPECT_EQ(alerts[2].id, 5u);
}

TEST(PortScanDetectorTest, ConfigSanitization) {
    PortScanConfig cfg{};
    cfg.port_threshold = 1000;
    cfg.recovery_port_threshold = 1000;
    cfg.entry_ttl = Timestamp{1'000'000};
    cfg.window_duration = Timestamp{5'000'000};
    PortScanDetector detector{cfg};

    for (uint16_t p = 1; p <= 64; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{p * 1'000}));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().state, AlertState::Active);

    detector.on_tick(Timestamp{10'000'000});
    EXPECT_EQ(detector.alerts().front().state, AlertState::Resolved);
}

TEST(PortScanDetectorTest, ResetClearsState) {
    PortScanDetector detector{};

    for (uint16_t p = 1; p <= 25; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{p * 1'000}));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);

    detector.reset();

    EXPECT_EQ(detector.tracked_source_count(), 0u);
    EXPECT_TRUE(detector.alerts().empty());
    EXPECT_TRUE(detector.active_alerts().empty());
    EXPECT_EQ(detector.untracked_source_packets(), 0u);

    for (uint16_t p = 1; p <= 25; ++p) {
        detector.record(make_tcp_packet({10, 0, 0, 66}, {10, 0, 0, 1}, 10000, p, 0x02, Timestamp{p * 1'000}));
    }

    ASSERT_EQ(detector.alerts().size(), 1u);
    EXPECT_EQ(detector.alerts().front().id, 1u);
}