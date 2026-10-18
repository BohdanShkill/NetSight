#include <gtest/gtest.h>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "netsight/concurrency/BoundedQueue.hpp"
#include "netsight/core/Types.hpp"

using namespace netsight;
using namespace std::chrono_literals;

TEST(BoundedQueueTest, ZeroCapacityThrows) {
    EXPECT_THROW(BoundedQueue<int> q(0), std::invalid_argument);
}

TEST(BoundedQueueTest, FifoOrder) {
    BoundedQueue<int> q(3);
    EXPECT_EQ(q.try_push(1), PushResult::Pushed);
    EXPECT_EQ(q.try_push(2), PushResult::Pushed);
    EXPECT_EQ(q.try_push(3), PushResult::Pushed);

    EXPECT_EQ(q.size(), 3u);
    EXPECT_EQ(q.pop_for(0ms), 1);
    EXPECT_EQ(q.pop_for(0ms), 2);
    EXPECT_EQ(q.pop_for(0ms), 3);
    EXPECT_EQ(q.size(), 0u);
}

TEST(BoundedQueueTest, TryPushWhenFullDropsNewest) {
    BoundedQueue<int> q(2);
    EXPECT_EQ(q.try_push(1), PushResult::Pushed);
    EXPECT_EQ(q.try_push(2), PushResult::Pushed);

    EXPECT_EQ(q.try_push(3), PushResult::Dropped);
    EXPECT_EQ(q.dropped(), 1u);

    EXPECT_EQ(q.pop_for(0ms), 1);
    EXPECT_EQ(q.pop_for(0ms), 2);
    EXPECT_EQ(q.pop_for(0ms), std::nullopt);
}

TEST(BoundedQueueTest, DroppedItemIsNotMovedFrom) {
    BoundedQueue<std::unique_ptr<int>> q(1);
    auto p1 = std::make_unique<int>(10);
    EXPECT_EQ(q.try_push(std::move(p1)), PushResult::Pushed);

    auto p2 = std::make_unique<int>(20);
    EXPECT_EQ(q.try_push(std::move(p2)), PushResult::Dropped);
    ASSERT_NE(p2, nullptr);
    EXPECT_EQ(*p2, 20);
}

TEST(BoundedQueueTest, PopTimesOutOnEmpty) {
    BoundedQueue<int> q(2);
    const auto start = std::chrono::steady_clock::now();
    const auto item = q.pop_for(50ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(item, std::nullopt);
    EXPECT_GE(elapsed, 45ms);
    EXPECT_LE(elapsed, 2000ms);
}

TEST(BoundedQueueTest, ZeroTimeoutIsNonBlocking) {
    BoundedQueue<int> q(2);
    EXPECT_EQ(q.pop_for(0ms), std::nullopt);

    q.try_push(42);
    EXPECT_EQ(q.pop_for(0ms), 42);
}

TEST(BoundedQueueTest, CloseRejectsPushButDrains) {
    BoundedQueue<int> q(2);
    q.try_push(1);
    q.try_push(2);

    q.close();

    EXPECT_EQ(q.try_push(3), PushResult::Closed);
    EXPECT_EQ(q.dropped(), 0u);
    EXPECT_EQ(q.push(4), PushResult::Closed);

    EXPECT_EQ(q.pop_for(10ms), 1);
    EXPECT_EQ(q.pop_for(10ms), 2);

    const auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(q.pop_for(10s), std::nullopt);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, 1s);

    EXPECT_TRUE(q.is_drained());
}

TEST(BoundedQueueTest, ClosedAndFullReportsClosed) {
    BoundedQueue<int> q(1);
    q.try_push(1);
    q.close();

    EXPECT_EQ(q.try_push(2), PushResult::Closed);
    EXPECT_EQ(q.dropped(), 0u);
}

TEST(BoundedQueueTest, CloseIsIdempotent) {
    BoundedQueue<int> q(2);
    q.close();
    q.close();
    EXPECT_TRUE(q.is_drained());
}

TEST(BoundedQueueTest, WorksWithRawPacket) {
    BoundedQueue<RawPacket> q(1);
    const std::vector<Byte> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
    RawPacket pkt(Timestamp{1000}, bytes.data(), bytes.size(), static_cast<std::uint32_t>(bytes.size()));

    EXPECT_EQ(q.try_push(std::move(pkt)), PushResult::Pushed);
    auto popped = q.pop_for(10ms);
    ASSERT_TRUE(popped.has_value());
    EXPECT_EQ(popped->data.size(), 4u);
    EXPECT_EQ(popped->data[0], 0xDE);
}

TEST(BoundedQueueTest, CloseWakesBlockedConsumer) {
    BoundedQueue<int> q(2);
    std::promise<std::optional<int>> prom;
    auto fut = prom.get_future();

    std::thread consumer([&] {
        prom.set_value(q.pop_for(30s));
    });

    std::this_thread::sleep_for(10ms);
    q.close();

    ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(fut.get(), std::nullopt);

    consumer.join();
}

TEST(BoundedQueueTest, CloseWakesBlockedProducer) {
    BoundedQueue<int> q(1);
    q.try_push(1);

    std::promise<PushResult> prom;
    auto fut = prom.get_future();

    std::thread producer([&] {
        prom.set_value(q.push(2));
    });

    std::this_thread::sleep_for(10ms);
    q.close();

    ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(fut.get(), PushResult::Closed);

    producer.join();
}

TEST(BoundedQueueTest, BlockingPushWaitsForSpace) {
    BoundedQueue<int> q(1);
    q.try_push(1);

    std::promise<PushResult> prom;
    auto fut = prom.get_future();

    std::thread producer([&] {
        prom.set_value(q.push(2));
    });

    std::this_thread::sleep_for(10ms);
    EXPECT_EQ(q.pop_for(50ms), 1);

    ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(fut.get(), PushResult::Pushed);
    EXPECT_EQ(q.pop_for(50ms), 2);

    producer.join();
}

TEST(BoundedQueueTest, StressBlockingIsLossless) {
    BoundedQueue<int> q(64);
    constexpr int N = 100'000;
    std::vector<int> received;
    received.reserve(N);

    std::thread consumer([&] {
        while (true) {
            auto item = q.pop_for(100ms);
            if (item) {
                received.push_back(*item);
            } else if (q.is_drained()) {
                break;
            }
        }
    });

    std::thread producer([&] {
        for (int i = 0; i < N; ++i) {
            q.push(std::move(i));
        }
        q.close();
    });

    producer.join();
    consumer.join();

    EXPECT_EQ(received.size(), static_cast<std::size_t>(N));
    EXPECT_EQ(q.dropped(), 0u);

    for (int i = 0; i < N; ++i) {
        if (received[i] != i) {
            FAIL() << "Mismatch at index " << i << ": expected " << i << ", got " << received[i];
        }
    }
}

TEST(BoundedQueueTest, StressTryPushAccounting) {
    BoundedQueue<int> q(64);
    constexpr int N = 100'000;
    std::vector<int> received;
    received.reserve(N);

    std::thread consumer([&] {
        while (true) {
            auto item = q.pop_for(100ms);
            if (item) {
                received.push_back(*item);
            } else if (q.is_drained()) {
                break;
            }
        }
    });

    std::thread producer([&] {
        for (int i = 0; i < N; ++i) {
            q.try_push(std::move(i));
        }
        q.close();
    });

    producer.join();
    consumer.join();

    EXPECT_EQ(received.size() + q.dropped(), static_cast<std::size_t>(N));

    for (std::size_t i = 1; i < received.size(); ++i) {
        EXPECT_GT(received[i], received[i - 1]);
    }
}

TEST(BoundedQueueTest, LastItemBeforeCloseIsNeverLost) {
    for (int iter = 0; iter < 500; ++iter) {
        BoundedQueue<int> q(10);

        std::thread producer([&] {
            q.try_push(std::move(iter));
            q.close();
        });

        std::vector<int> received;
        std::thread consumer([&] {
            while (true) {
                auto item = q.pop_for(20ms);
                if (item) {
                    received.push_back(*item);
                } else if (q.is_drained()) {
                    break;
                }
            }
        });

        producer.join();
        consumer.join();

        ASSERT_EQ(received.size(), 1u);
        EXPECT_EQ(received[0], iter);
    }
}