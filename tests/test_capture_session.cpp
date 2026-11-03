#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "netsight/pipeline/CaptureSession.hpp"
#include "netsight/source/PcapFileReader.hpp"
#include "netsight/analytics/StatsAggregator.hpp"
#include "support/FakePacketSource.hpp"
#include "support/PacketBuilder.hpp"
#include "support/PcapWriter.hpp"
#include "support/ReadAll.hpp"
#include "support/TempFile.hpp"

using namespace netsight;
using namespace netsight::test;

namespace {

std::vector<RawPacket> make_packets(std::size_t n, std::uint16_t dst_port = 80) {
    std::vector<RawPacket> pkts;
    pkts.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        pkts.push_back(
            PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {10, 0, 0, 2}).tcp(10000, dst_port).build()
        );
    }
    return pkts;
}

}

TEST(CaptureSessionTest, DeliversAllAndEndsWithEndOfStream) {
    auto pkts = make_packets(100);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    std::size_t delivered_count = 0;
    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            ++delivered_count;
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    session.stop();

    EXPECT_EQ(session.stop_reason(), StopReason::EndOfStream);
    EXPECT_EQ(delivered_count, 100u);

    const auto counters = session.counters();
    EXPECT_EQ(counters.received, 100u);
    EXPECT_EQ(counters.processed, 100u);
    EXPECT_EQ(counters.delivered, 100u);
    EXPECT_EQ(counters.dropped, 0u);
}

TEST(CaptureSessionTest, FilterAppliedBeforeSink) {
    std::vector<RawPacket> pkts;
    pkts.reserve(100);
    for (std::size_t i = 0; i < 30; ++i) {
        pkts.push_back(PacketBuilder{}.ethernet(0x0800).ipv4().tcp(10000, 80).build());
    }
    for (std::size_t i = 0; i < 70; ++i) {
        pkts.push_back(PacketBuilder{}.ethernet(0x0800).ipv4().tcp(10000, 443).build());
    }

    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;
    cfg.filter.port = 80;

    std::size_t delivered_count = 0;
    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            ++delivered_count;
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    session.stop();

    EXPECT_EQ(delivered_count, 30u);
    const auto counters = session.counters();
    EXPECT_EQ(counters.received, 100u);
    EXPECT_EQ(counters.processed, 100u);
    EXPECT_EQ(counters.delivered, 30u);
    EXPECT_EQ(counters.dropped, 0u);
}

TEST(CaptureSessionTest, SinkRunsOnSingleWorkerThread) {
    auto pkts = make_packets(20);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    const auto test_tid = std::this_thread::get_id();
    std::thread::id worker_tid{};
    bool all_threads_match = true;

    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            const auto current_tid = std::this_thread::get_id();
            if (worker_tid == std::thread::id{}) {
                worker_tid = current_tid;
            } else if (worker_tid != current_tid) {
                all_threads_match = false;
            }
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    session.stop();

    EXPECT_TRUE(all_threads_match);
    EXPECT_NE(worker_tid, std::thread::id{});
    EXPECT_NE(worker_tid, test_tid);
}

TEST(CaptureSessionTest, StartValidation) {
    CaptureSession s1(nullptr, SessionConfig{}, [](const ParsedPacket&) {});
    EXPECT_FALSE(s1.start());
    EXPECT_NE(s1.last_error().find("source is null"), std::string::npos);

    auto src2 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    CaptureSession s2(std::move(src2), SessionConfig{}, nullptr);
    EXPECT_FALSE(s2.start());
    EXPECT_NE(s2.last_error().find("sink must not be empty"), std::string::npos);

    SessionConfig cfg3;
    cfg3.queue_capacity = 0;
    auto src3 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    CaptureSession s3(std::move(src3), cfg3, [](const ParsedPacket&) {});
    EXPECT_FALSE(s3.start());
    EXPECT_NE(s3.last_error().find("queue capacity must be in range"), std::string::npos);

    SessionConfig cfg4;
    cfg4.queue_capacity = 1048577;
    auto src4 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    CaptureSession s4(std::move(src4), cfg4, [](const ParsedPacket&) {});
    EXPECT_FALSE(s4.start());
    EXPECT_NE(s4.last_error().find("queue capacity must be in range"), std::string::npos);

    SessionConfig cfg5;
    cfg5.filter.port = 0;
    auto src5 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    CaptureSession s5(std::move(src5), cfg5, [](const ParsedPacket&) {});
    EXPECT_FALSE(s5.start());
    EXPECT_NE(s5.last_error().find("filter port must be 1..65535"), std::string::npos);

    SessionConfig cfg6;
    cfg6.filter.ip = IpAddress{};
    auto src6 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    CaptureSession s6(std::move(src6), cfg6, [](const ParsedPacket&) {});
    EXPECT_FALSE(s6.start());
    EXPECT_NE(s6.last_error().find("filter ip is invalid"), std::string::npos);

    auto src7 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Unknown);
    CaptureSession s7(std::move(src7), SessionConfig{}, [](const ParsedPacket&) {});
    EXPECT_FALSE(s7.start());
    EXPECT_NE(s7.last_error().find("unsupported link type"), std::string::npos);

    auto src8 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    CaptureSession s8(std::move(src8), SessionConfig{}, [](const ParsedPacket&) {});
    EXPECT_TRUE(s8.start());
    EXPECT_FALSE(s8.start());
    EXPECT_NE(s8.last_error().find("session already started"), std::string::npos);
    s8.stop();
}

TEST(CaptureSessionTest, DropNewestUnderBackpressure) {
    auto pkts = make_packets(200);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.queue_capacity = 4;
    cfg.overflow = OverflowPolicy::DropNewest;

    std::mutex mtx;
    std::condition_variable cv;
    bool first_packet = true;
    std::size_t delivered = 0;

    std::unique_ptr<CaptureSession> session;
    session = std::make_unique<CaptureSession>(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            if (first_packet) {
                first_packet = false;
                std::unique_lock<std::mutex> lock(mtx);
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                while (std::chrono::steady_clock::now() < deadline) {
                    if (session->counters().received >= 200) {
                        break;
                    }
                    cv.wait_for(lock, std::chrono::milliseconds(10));
                }
            }
            ++delivered;
        }
    );

    ASSERT_TRUE(session->start());
    EXPECT_TRUE(session->wait_for(std::chrono::seconds(5)));
    session->stop();

    const auto counters = session->counters();
    EXPECT_GT(counters.dropped, 0u);
    EXPECT_EQ(counters.received, counters.processed + counters.dropped);
    EXPECT_EQ(counters.delivered, delivered);
}

TEST(CaptureSessionTest, BlockPolicyLosesNothing) {
    auto pkts = make_packets(500);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.queue_capacity = 2;
    cfg.overflow = OverflowPolicy::Block;

    std::size_t delivered = 0;
    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            ++delivered;
            if (delivered % 50 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(10)));
    session.stop();

    const auto counters = session.counters();
    EXPECT_EQ(counters.dropped, 0u);
    EXPECT_EQ(counters.received, 500u);
    EXPECT_EQ(counters.processed, 500u);
    EXPECT_EQ(counters.delivered, 500u);
}

TEST(CaptureSessionTest, StopWhileRunningReturnsPromptly) {
    auto pkts = make_packets(50);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet, std::nullopt, true);

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    CaptureSession session(std::move(source), cfg, [](const ParsedPacket&) {});
    ASSERT_TRUE(session.start());

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    const auto start_time = std::chrono::steady_clock::now();
    session.stop();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time);

    EXPECT_LT(elapsed.count(), 1000);
    EXPECT_EQ(session.stop_reason(), StopReason::StoppedByUser);

    const auto counters = session.counters();
    EXPECT_EQ(counters.received, counters.processed + counters.dropped);
}

TEST(CaptureSessionTest, StopIsIdempotentAndSafeWithoutStart) {
    {
        auto source = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
        CaptureSession session(std::move(source), SessionConfig{}, [](const ParsedPacket&) {});
        session.stop();
    }

    {
        auto pkts = make_packets(10);
        auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);
        CaptureSession session(std::move(source), SessionConfig{}, [](const ParsedPacket&) {});
        ASSERT_TRUE(session.start());
        session.stop();
        session.stop();
    }
}

TEST(CaptureSessionTest, DestructorStopsRunningSession) {
    auto pkts = make_packets(100);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet, std::nullopt, true);
    {
        CaptureSession session(std::move(source), SessionConfig{}, [](const ParsedPacket&) {});
        ASSERT_TRUE(session.start());
    }
}

TEST(CaptureSessionTest, SinkExceptionEndsWithErrorNoDeadlock) {
    auto pkts = make_packets(1000);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.queue_capacity = 1;
    cfg.overflow = OverflowPolicy::Block;

    std::size_t delivered = 0;
    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            ++delivered;
            if (delivered == 3) {
                throw std::runtime_error("boom");
            }
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    EXPECT_EQ(session.stop_reason(), StopReason::Error);
    EXPECT_NE(session.last_error().find("boom"), std::string::npos);
    EXPECT_EQ(session.counters().delivered, 2u);

    session.stop();
}

TEST(CaptureSessionTest, SourceErrorPropagates) {
    auto pkts = make_packets(20);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet, 5);

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    std::size_t delivered = 0;
    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            ++delivered;
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    session.stop();

    EXPECT_EQ(session.stop_reason(), StopReason::Error);
    EXPECT_NE(session.last_error().find("Simulated"), std::string::npos);
    EXPECT_EQ(delivered, 5u);
}

TEST(CaptureSessionTest, SourceStartFailureCleansUp) {
    auto source = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    source->start([](RawPacket) {}, [](StopReason) {});
    source->stop();

    CaptureSession session(std::move(source), SessionConfig{}, [](const ParsedPacket&) {});
    EXPECT_FALSE(session.start());
    EXPECT_NE(session.last_error().find("source failed to start"), std::string::npos);
}

TEST(CaptureSessionTest, StopFromSinkDoesNotDeadlock) {
    auto pkts = make_packets(100);
    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    std::unique_ptr<CaptureSession> session;
    session = std::make_unique<CaptureSession>(
        std::move(source),
        cfg,
        [&](const ParsedPacket&) {
            session->stop();
        }
    );

    ASSERT_TRUE(session->start());
    EXPECT_TRUE(session->wait_for(std::chrono::seconds(2)));
    session->stop();
}

TEST(CaptureSessionTest, EndToEndGeneratedPcap) {
    const auto ip_target = *parse_ip_address("10.0.0.1");
    std::mt19937 rng(42);

    std::vector<RawPacket> packets;
    packets.reserve(1000);

    std::size_t gt_ip_delivered = 0;
    std::size_t gt_port_delivered = 0;
    std::map<TransportProtocol, std::size_t> gt_port_transports;

    PacketFilter filter_ip;
    filter_ip.ip = ip_target;

    PacketFilter filter_port;
    filter_port.port = 80;

    for (std::size_t i = 0; i < 1000; ++i) {
        const auto branch = rng() % 7;
        RawPacket pkt(Timestamp{static_cast<std::int64_t>(i * 1000)}, nullptr, 0, 0);

        if (branch == 0) {
            pkt = PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {192, 168, 1, 2}).tcp(12345, 80).build(Timestamp{static_cast<std::int64_t>(i * 1000)});
        } else if (branch == 1) {
            pkt = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {8, 8, 8, 8}, 17).udp(5000, 53).payload("dns").build(Timestamp{static_cast<std::int64_t>(i * 1000)});
        } else if (branch == 2) {
            pkt = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {1, 1, 1, 1}, 1).icmp(8, 0).build(Timestamp{static_cast<std::int64_t>(i * 1000)});
        } else if (branch == 3) {
            pkt = PacketBuilder{}.ethernet(0x0806).bytes(28, 0).build(Timestamp{static_cast<std::int64_t>(i * 1000)});
        } else if (branch == 4) {
            pkt = PacketBuilder{}.ethernet(0x86DD).ipv6().tcp(1000, 80).build(Timestamp{static_cast<std::int64_t>(i * 1000)});
        } else if (branch == 5) {
            pkt = PacketBuilder{}.ethernet(0x8100).vlan(100, 0x0800).ipv4({192, 168, 1, 10}, {10, 0, 0, 1}).tcp(2000, 80).build(Timestamp{static_cast<std::int64_t>(i * 1000)});
        } else {
            auto full = PacketBuilder{}.ethernet(0x0800).ipv4({192, 168, 1, 1}, {192, 168, 1, 2}).tcp(1234, 80).build(Timestamp{static_cast<std::int64_t>(i * 1000)});
            pkt = RawPacket(full.timestamp, full.data.data(), 30, full.original_length);
        }

        auto parsed = parse_packet(pkt, LinkType::Ethernet);
        if (filter_ip.matches(parsed)) {
            ++gt_ip_delivered;
        }
        if (filter_port.matches(parsed)) {
            ++gt_port_delivered;
            gt_port_transports[parsed.transport]++;
        }

        packets.push_back(std::move(pkt));
    }

    TempFile tmp;
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, packets));

    {
        std::string err;
        auto reader = PcapFileReader::open(tmp.path().string(), err);
        ASSERT_NE(reader, nullptr) << err;

        SessionConfig cfg;
        cfg.overflow = OverflowPolicy::Block;
        cfg.filter = filter_ip;

        std::size_t delivered = 0;
        CaptureSession session(
            std::move(reader),
            cfg,
            [&](const ParsedPacket&) {
                ++delivered;
            }
        );

        ASSERT_TRUE(session.start());
        EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
        session.stop();

        EXPECT_EQ(session.stop_reason(), StopReason::EndOfStream);
        const auto counters = session.counters();
        EXPECT_EQ(counters.dropped, 0u);
        EXPECT_EQ(counters.processed, 1000u);
        EXPECT_EQ(counters.delivered, gt_ip_delivered);
        EXPECT_EQ(delivered, gt_ip_delivered);
    }

    {
        std::string err;
        auto reader = PcapFileReader::open(tmp.path().string(), err);
        ASSERT_NE(reader, nullptr) << err;

        SessionConfig cfg;
        cfg.overflow = OverflowPolicy::Block;
        cfg.filter = filter_port;

        std::size_t delivered = 0;
        std::map<TransportProtocol, std::size_t> actual_transports;
        CaptureSession session(
            std::move(reader),
            cfg,
            [&](const ParsedPacket& p) {
                ++delivered;
                actual_transports[p.transport]++;
            }
        );

        ASSERT_TRUE(session.start());
        EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
        session.stop();

        EXPECT_EQ(session.stop_reason(), StopReason::EndOfStream);
        const auto counters = session.counters();
        EXPECT_EQ(counters.dropped, 0u);
        EXPECT_EQ(counters.processed, 1000u);
        EXPECT_EQ(counters.delivered, gt_port_delivered);
        EXPECT_EQ(delivered, gt_port_delivered);
        EXPECT_EQ(actual_transports, gt_port_transports);
    }
}

TEST(CaptureSessionTest, GoldenFileMatchesDirectRead) {
    const std::string golden_path = std::string(NETSIGHT_TEST_DATA_DIR) + "/lo_tcp.pcap";
    std::string err;

    auto direct_reader = PcapFileReader::open(golden_path, err);
    ASSERT_NE(direct_reader, nullptr) << err;

    auto direct_result = read_all(*direct_reader);
    ASSERT_EQ(direct_result.reason, StopReason::EndOfStream);
    const auto expected_count = direct_result.packets.size();
    ASSERT_GT(expected_count, 0u);

    auto session_reader = PcapFileReader::open(golden_path, err);
    ASSERT_NE(session_reader, nullptr) << err;

    std::size_t delivered = 0;
    bool all_ok = true;
    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    CaptureSession session(
        std::move(session_reader),
        cfg,
        [&](const ParsedPacket& p) {
            ++delivered;
            if (p.status != ParseStatus::Ok) {
                all_ok = false;
            }
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    session.stop();

    EXPECT_EQ(session.stop_reason(), StopReason::EndOfStream);
    EXPECT_EQ(delivered, expected_count);
    EXPECT_TRUE(all_ok);

    const auto counters = session.counters();
    EXPECT_EQ(counters.dropped, 0u);
    EXPECT_EQ(counters.received, expected_count);
    EXPECT_EQ(counters.processed, expected_count);
    EXPECT_EQ(counters.delivered, expected_count);
}

TEST(CaptureSessionTest, EmptyPcapFinishesImmediately) {
    TempFile tmp;
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, {}));

    std::string err;
    auto reader = PcapFileReader::open(tmp.path().string(), err);
    ASSERT_NE(reader, nullptr) << err;

    std::size_t delivered = 0;
    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;

    CaptureSession session(
        std::move(reader),
        cfg,
        [&](const ParsedPacket&) {
            ++delivered;
        }
    );

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(1)));
    session.stop();

    EXPECT_EQ(session.stop_reason(), StopReason::EndOfStream);
    EXPECT_EQ(delivered, 0u);

    const auto counters = session.counters();
    EXPECT_EQ(counters.received, 0u);
    EXPECT_EQ(counters.dropped, 0u);
    EXPECT_EQ(counters.processed, 0u);
    EXPECT_EQ(counters.delivered, 0u);
}

TEST(CaptureSessionTest, InvalidTickIntervalRejected) {
    auto source1 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    SessionConfig cfg1;
    cfg1.tick_interval = std::chrono::milliseconds(0);
    CaptureSession s1(std::move(source1), cfg1, [](const ParsedPacket&) {});
    EXPECT_FALSE(s1.start());
    EXPECT_NE(s1.last_error().find("tick interval"), std::string::npos);

    auto source2 = std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);
    SessionConfig cfg2;
    cfg2.tick_interval = std::chrono::milliseconds(-10);
    CaptureSession s2(std::move(source2), cfg2, [](const ParsedPacket&) {});
    EXPECT_FALSE(s2.start());
    EXPECT_NE(s2.last_error().find("tick interval"), std::string::npos);
}

TEST(CaptureSessionTest, PeriodicTickFiresDuringIdleAndFinalTickOnStop) {
    auto source = std::make_unique<FakePacketSource>(
        std::vector<RawPacket>{},
        LinkType::Ethernet,
        std::nullopt,
        true
    );

    std::atomic<int> tick_count{0};
    std::mutex cv_m;
    std::condition_variable cv;

    SessionConfig cfg;
    cfg.tick_interval = std::chrono::milliseconds(25);
    cfg.on_tick = [&]() {
        tick_count.fetch_add(1, std::memory_order_relaxed);
        cv.notify_one();
    };

    CaptureSession session(std::move(source), cfg, [](const ParsedPacket&) {});
    ASSERT_TRUE(session.start());

    {
        std::unique_lock<std::mutex> lock(cv_m);
        cv.wait_for(lock, std::chrono::seconds(2), [&]() {
            return tick_count.load(std::memory_order_relaxed) >= 2;
        });
    }

    const int ticks_before_stop = tick_count.load(std::memory_order_relaxed);
    EXPECT_GE(ticks_before_stop, 2);

    session.stop();
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(2)));

    const int ticks_after_stop = tick_count.load(std::memory_order_relaxed);
    EXPECT_GT(ticks_after_stop, ticks_before_stop);
}

TEST(CaptureSessionTest, EndToEndSessionWithStatsAggregator) {
    std::vector<RawPacket> pkts;
    pkts.reserve(100);
    for (std::size_t i = 0; i < 50; ++i) {
        pkts.push_back(PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 1}, {192, 168, 1, 1}).tcp(10000, 80).build(Timestamp{static_cast<std::int64_t>(i * 1000)}));
    }
    for (std::size_t i = 50; i < 100; ++i) {
        pkts.push_back(PacketBuilder{}.ethernet(0x0800).ipv4({10, 0, 0, 2}, {192, 168, 1, 1}).tcp(10000, 443).build(Timestamp{static_cast<std::int64_t>(i * 1000)}));
    }

    auto source = std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet);

    StatsAggregator aggregator{};

    SessionConfig cfg;
    cfg.overflow = OverflowPolicy::Block;
    cfg.filter.port = 80;
    cfg.tick_interval = std::chrono::milliseconds(50);

    CaptureSession* session_ptr = nullptr;
    cfg.on_tick = [&]() {
        if (session_ptr) {
            const auto c = session_ptr->counters();
            DropCounters drops{};
            drops.filtered_out = c.processed - c.delivered;
            drops.queue_dropped = c.dropped;
            aggregator.publish(drops);
        }
    };

    CaptureSession session(
        std::move(source),
        cfg,
        [&](const ParsedPacket& pkt) {
            aggregator.record(pkt);
        }
    );
    session_ptr = &session;

    ASSERT_TRUE(session.start());
    EXPECT_TRUE(session.wait_for(std::chrono::seconds(5)));
    session.stop();

    const auto counters = session.counters();
    EXPECT_EQ(counters.received, 100u);
    EXPECT_EQ(counters.processed, 100u);
    EXPECT_EQ(counters.delivered, 50u);

    const auto snap = aggregator.latest_snapshot();
    ASSERT_NE(snap, nullptr);
    EXPECT_EQ(snap->total_packets, 50u);
    EXPECT_EQ(snap->drops.filtered_out, 50u);
    EXPECT_EQ(snap->drops.queue_dropped, 0u);
    EXPECT_GE(snap->snapshot_seq, 1u);
}