#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "netsight/analytics/Alert.hpp"
#include "netsight/analytics/TrafficAnalyzer.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "netsight/pipeline/CaptureSession.hpp"
#include "support/FakePacketSource.hpp"
#include "support/PacketBuilder.hpp"

using namespace netsight;
using namespace netsight::test;

namespace {

std::vector<RawPacket> generate_normal_traffic(int num_connections,
                                               int64_t start_us = 0,
                                               int64_t duration_us = 30'000'000,
                                               uint32_t seed = 42) {
    std::mt19937 rng(seed);
    std::vector<RawPacket> pkts;
    pkts.reserve(num_connections * 10);

    const std::array<std::array<uint8_t, 4>, 3> servers = {{
        {192, 168, 10, 1},
        {192, 168, 10, 2},
        {192, 168, 10, 3}
    }};
    const std::array<uint16_t, 3> server_ports = {443, 80, 22};

    for (int i = 0; i < num_connections; ++i) {
        const uint8_t client_last = static_cast<uint8_t>(1 + (rng() % 30));
        const std::array<uint8_t, 4> client_ip = {10, 1, 0, client_last};
        const std::size_t s_idx = rng() % servers.size();
        const auto& s_ip = servers[s_idx];
        const uint16_t s_port = server_ports[s_idx];
        const uint16_t c_port = static_cast<uint16_t>(10000 + (rng() % 50000));

        const int64_t max_offset = std::max<int64_t>(1, duration_us - 100'000);
        int64_t t = start_us + (rng() % max_offset);

        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4(client_ip, s_ip, 6)
                                      .tcp(c_port, s_port, 0x02)
                                      .build(Timestamp{t}));
        t += 100;

        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4(s_ip, client_ip, 6)
                                      .tcp(s_port, c_port, 0x12)
                                      .build(Timestamp{t}));
        t += 100;

        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4(client_ip, s_ip, 6)
                                      .tcp(c_port, s_port, 0x10)
                                      .build(Timestamp{t}));
        t += 100;

        const int data_count = 2 + static_cast<int>(rng() % 5);
        for (int d = 0; d < data_count; ++d) {
            if (d % 2 == 0) {
                pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                              .ipv4(client_ip, s_ip, 6)
                                              .tcp(c_port, s_port, 0x18)
                                              .build(Timestamp{t}));
            } else {
                pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                              .ipv4(s_ip, client_ip, 6)
                                              .tcp(s_port, c_port, 0x18)
                                              .build(Timestamp{t}));
            }
            t += 100;
        }

        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4(client_ip, s_ip, 6)
                                      .tcp(c_port, s_port, 0x11)
                                      .build(Timestamp{t}));

        if (i % 5 == 0) {
            pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                          .ipv4(client_ip, std::array<uint8_t, 4>{192, 168, 10, 1}, 17)
                                          .udp(c_port, 53)
                                          .build(Timestamp{t + 50}));
        }
    }

    std::sort(pkts.begin(), pkts.end(), [](const RawPacket& a, const RawPacket& b) noexcept {
        return a.timestamp < b.timestamp;
    });

    return pkts;
}

std::vector<RawPacket> make_mixed_scenario_packets() {
    auto pkts = generate_normal_traffic(200, 0, 5'000'000, 42);

    for (uint32_t i = 1; i <= 150; ++i) {
        const uint8_t b3 = static_cast<uint8_t>((i >> 8) & 0xFF);
        const uint8_t b4 = static_cast<uint8_t>(i & 0xFF);
        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4({172, 16, b3, b4}, {10, 0, 0, 1}, 6)
                                      .tcp(static_cast<uint16_t>(10000 + (i % 50000)), 443, 0x02)
                                      .build(Timestamp{2'000'000 + i * 1'000}));
    }

    for (uint16_t p = 1; p <= 40; ++p) {
        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4({10, 0, 0, 99}, {192, 168, 1, 1}, 6)
                                      .tcp(10000, p, 0x02)
                                      .build(Timestamp{3'000'000 + p * 5'000}));
    }

    std::sort(pkts.begin(), pkts.end(), [](const RawPacket& a, const RawPacket& b) noexcept {
        return a.timestamp < b.timestamp;
    });

    return pkts;
}

}

TEST(TrafficAnalyzerTest, SeededNormalTrafficProducesNoAlerts) {
    TrafficAnalyzer analyzer{};

    auto pkts = generate_normal_traffic(2000, 0, 30'000'000, 42);
    for (const auto& raw : pkts) {
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{30'000'000});
    ASSERT_NE(snap, nullptr);
    EXPECT_TRUE(snap->alerts.empty());
    EXPECT_EQ(snap->drops.untracked_syn_targets, 0u);
    EXPECT_EQ(snap->drops.untracked_scan_sources, 0u);
    EXPECT_GT(snap->total_packets, 5000u);
}

TEST(TrafficAnalyzerTest, FlashCrowdWithHandshakesIsNotSynFlood) {
    TrafficAnalyzer analyzer{};

    std::vector<RawPacket> pkts;
    pkts.reserve(900);
    for (int i = 0; i < 300; ++i) {
        const int64_t t = i * 2'500;
        const uint16_t c_port = static_cast<uint16_t>(10000 + i);

        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4({10, 0, 0, 5}, {192, 168, 10, 1}, 6)
                                      .tcp(c_port, 443, 0x02)
                                      .build(Timestamp{t}));
        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4({192, 168, 10, 1}, {10, 0, 0, 5}, 6)
                                      .tcp(443, c_port, 0x12)
                                      .build(Timestamp{t + 50}));
        pkts.push_back(PacketBuilder{}.ethernet(0x0800)
                                      .ipv4({10, 0, 0, 5}, {192, 168, 10, 1}, 6)
                                      .tcp(c_port, 443, 0x10)
                                      .build(Timestamp{t + 100}));
    }

    std::sort(pkts.begin(), pkts.end(), [](const RawPacket& a, const RawPacket& b) noexcept {
        return a.timestamp < b.timestamp;
    });

    for (const auto& raw : pkts) {
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{1'500'000});
    ASSERT_NE(snap, nullptr);
    EXPECT_TRUE(snap->alerts.empty());
}

TEST(TrafficAnalyzerTest, SpoofedSynFloodRaisesOnlySynFlood) {
    AnalyzerConfig cfg{};
    cfg.port_scan.max_tracked_sources = 512;
    TrafficAnalyzer analyzer{cfg};

    for (uint32_t i = 1; i <= 10'000; ++i) {
        const uint8_t b1 = 100;
        const uint8_t b2 = static_cast<uint8_t>((i >> 16) & 0xFF);
        const uint8_t b3 = static_cast<uint8_t>((i >> 8) & 0xFF);
        const uint8_t b4 = static_cast<uint8_t>(i & 0xFF);

        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({b1, b2, b3, b4}, {10, 0, 0, 1}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + (i % 50000)), 443, 0x02)
                                        .build(Timestamp{static_cast<int64_t>((i - 1) * 80)});
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{1'500'000});
    ASSERT_NE(snap, nullptr);
    ASSERT_EQ(snap->alerts.size(), 1u);
    EXPECT_EQ(snap->alerts.front().type, AlertType::SynFlood);
    EXPECT_EQ(snap->alerts.front().state, AlertState::Active);
    EXPECT_GT(snap->drops.untracked_scan_sources, 0u);
    EXPECT_EQ(snap->drops.untracked_syn_targets, 0u);
}

TEST(TrafficAnalyzerTest, VerticalScanRaisesOnlyPortScan) {
    TrafficAnalyzer analyzer{};

    for (uint16_t p = 1; p <= 1024; ++p) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 66}, {10, 0, 0, 1}, 6)
                                        .tcp(10000, p, 0x02)
                                        .build(Timestamp{static_cast<int64_t>(p * 800)});
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{1'500'000});
    ASSERT_NE(snap, nullptr);
    ASSERT_EQ(snap->alerts.size(), 1u);
    EXPECT_EQ(snap->alerts.front().type, AlertType::PortScan);
    EXPECT_EQ(snap->alerts.front().state, AlertState::Active);
}

TEST(TrafficAnalyzerTest, MixedAttackAlertsSortedAndUniqueByTypeAndId) {
    TrafficAnalyzer analyzer{};

    const auto pkts = make_mixed_scenario_packets();
    for (const auto& raw : pkts) {
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{4'000'000});
    ASSERT_NE(snap, nullptr);
    ASSERT_EQ(snap->alerts.size(), 2u);

    EXPECT_EQ(snap->alerts[0].type, AlertType::SynFlood);
    EXPECT_EQ(snap->alerts[0].id, 1u);

    EXPECT_EQ(snap->alerts[1].type, AlertType::PortScan);
    EXPECT_EQ(snap->alerts[1].id, 1u);

    EXPECT_LE(snap->alerts[0].started_at, snap->alerts[1].started_at);
}

TEST(TrafficAnalyzerTest, PacketTimeHousekeepingResolvesWithoutWallClock) {
    TrafficAnalyzer analyzer{};

    for (int i = 0; i < 150; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{10'000 + i * 2'000});
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    for (int i = 0; i < 40; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 2}, {192, 168, 1, 20}, 17)
                                        .udp(10000, 53)
                                        .build(Timestamp{1'500'000 + i * 500'000});
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{0});
    ASSERT_NE(snap, nullptr);
    ASSERT_EQ(snap->alerts.size(), 1u);
    EXPECT_EQ(snap->alerts.front().type, AlertType::SynFlood);
    EXPECT_EQ(snap->alerts.front().state, AlertState::Resolved);
    EXPECT_LE(snap->alerts.front().ended_at.count(), 3'000'000);
    EXPECT_GE(snap->alerts.front().ended_at.count(), 1'000'000);
}

TEST(TrafficAnalyzerTest, LiveTickWithWallClockResolvesIdleAttack) {
    TrafficAnalyzer analyzer{};

    for (int i = 0; i < 150; ++i) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 1}, {192, 168, 1, 10}, 6)
                                        .tcp(static_cast<uint16_t>(10000 + i), 80, 0x02)
                                        .build(Timestamp{10'000 + i * 2'000});
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap = analyzer.on_tick(Timestamp{12'000'000});
    ASSERT_NE(snap, nullptr);
    ASSERT_EQ(snap->alerts.size(), 1u);
    EXPECT_EQ(snap->alerts.front().type, AlertType::SynFlood);
    EXPECT_EQ(snap->alerts.front().state, AlertState::Resolved);
    EXPECT_EQ(snap->alerts.front().ended_at, Timestamp{12'000'000});
}

TEST(TrafficAnalyzerTest, EndToEndThroughCaptureSessionIsDeterministic) {
    const auto pkts = make_mixed_scenario_packets();

    auto run_pipeline = [&pkts](std::chrono::milliseconds tick_ms) {
        TrafficAnalyzer analyzer{};
        auto source = std::make_unique<FakePacketSource>(pkts, LinkType::Ethernet);

        SessionConfig cfg{};
        cfg.overflow = OverflowPolicy::Block;
        cfg.tick_interval = tick_ms;

        CaptureSession* session_ptr = nullptr;
        cfg.on_tick = [&]() {
            if (session_ptr) {
                const auto c = session_ptr->counters();
                DropCounters drops{};
                drops.filtered_out = c.processed - c.delivered;
                drops.queue_dropped = c.dropped;
                analyzer.on_tick(Timestamp{0}, drops);
            }
        };

        CaptureSession session(
            std::move(source),
            cfg,
            [&](const ParsedPacket& p) {
                analyzer.record(p);
            }
        );
        session_ptr = &session;

        EXPECT_TRUE(session.start());
        EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
        session.stop();

        return analyzer.latest_snapshot();
    };

    const auto snap1 = run_pipeline(std::chrono::milliseconds(1));
    const auto snap2 = run_pipeline(std::chrono::milliseconds(10'000));

    ASSERT_NE(snap1, nullptr);
    ASSERT_NE(snap2, nullptr);

    ASSERT_EQ(snap1->alerts.size(), snap2->alerts.size());
    for (std::size_t i = 0; i < snap1->alerts.size(); ++i) {
        EXPECT_EQ(snap1->alerts[i], snap2->alerts[i]);
    }

    EXPECT_EQ(snap1->drops.filtered_out, 0u);
    EXPECT_EQ(snap1->drops.queue_dropped, 0u);
    EXPECT_EQ(snap2->drops.filtered_out, 0u);
    EXPECT_EQ(snap2->drops.queue_dropped, 0u);
}

TEST(TrafficAnalyzerTest, ResetClearsAnalyzer) {
    TrafficAnalyzer analyzer{};

    for (uint16_t p = 1; p <= 30; ++p) {
        const auto raw = PacketBuilder{}.ethernet(0x0800)
                                        .ipv4({10, 0, 0, 66}, {10, 0, 0, 1}, 6)
                                        .tcp(10000, p, 0x02)
                                        .build(Timestamp{static_cast<int64_t>(p * 1'000)});
        analyzer.record(parse_packet(raw, LinkType::Ethernet));
    }

    const auto snap_before = analyzer.on_tick(Timestamp{100'000});
    ASSERT_NE(snap_before, nullptr);
    EXPECT_FALSE(snap_before->alerts.empty());
    EXPECT_GT(snap_before->total_packets, 0u);

    analyzer.reset();

    const auto snap_after = analyzer.latest_snapshot();
    ASSERT_NE(snap_after, nullptr);
    EXPECT_TRUE(snap_after->alerts.empty());
    EXPECT_EQ(snap_after->total_packets, 0u);
}