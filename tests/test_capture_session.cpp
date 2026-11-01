#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "netsight/pipeline/CaptureSession.hpp"
#include "support/FakePacketSource.hpp"
#include "support/PacketBuilder.hpp"

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