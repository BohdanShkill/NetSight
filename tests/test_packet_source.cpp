#include <gtest/gtest.h>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <vector>

#include "netsight/core/Types.hpp"
#include "netsight/source/IPacketSource.hpp"
#include "support/FakePacketSource.hpp"

using namespace netsight;
using namespace std::chrono_literals;

namespace {

RawPacket make_test_packet(std::uint8_t id) {
    const std::vector<Byte> bytes = {id, 0xAA, 0xBB};
    return RawPacket(Timestamp{id * 1000}, bytes.data(), bytes.size(), static_cast<std::uint32_t>(bytes.size()));
}

} 

TEST(PacketSourceContractTest, OrderedDeliveryAndCompletion) {
    const std::vector<RawPacket> input = {
        make_test_packet(1),
        make_test_packet(2),
        make_test_packet(3)
    };

    std::unique_ptr<IPacketSource> source =
        std::make_unique<FakePacketSource>(input, LinkType::Ethernet);

    std::vector<std::uint8_t> received_ids;
    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();

    const bool started = source->start(
        [&received_ids](RawPacket pkt) {
            if (!pkt.data.empty()) {
                received_ids.push_back(pkt.data[0]);
            }
        },
        [&completion_promise](StopReason reason) {
            completion_promise.set_value(reason);
        });

    ASSERT_TRUE(started);

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(completion_future.get(), StopReason::EndOfStream);

    const std::vector<std::uint8_t> expected_ids = {1, 2, 3};
    EXPECT_EQ(received_ids, expected_ids);
    EXPECT_FALSE(source->is_running());
}

TEST(PacketSourceContractTest, IdempotentStop) {
    std::unique_ptr<IPacketSource> source =
        std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet, std::nullopt, true);

    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();

    ASSERT_TRUE(source->start([](RawPacket) {},
                              [&completion_promise](StopReason reason) {
                                  completion_promise.set_value(reason);
                              }));

    EXPECT_TRUE(source->is_running());

    source->stop();
    source->stop();

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(completion_future.get(), StopReason::StoppedByUser);
    EXPECT_FALSE(source->is_running());
}

TEST(PacketSourceContractTest, StopInsideCallbackDeadlockImmunity) {
    const std::vector<RawPacket> input = {
        make_test_packet(1),
        make_test_packet(2),
        make_test_packet(3)
    };

    auto source = std::make_unique<FakePacketSource>(input, LinkType::Ethernet, std::nullopt, true);
    IPacketSource* raw_source = source.get();

    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();
    std::size_t packets_handled = 0;

    const bool started = source->start(
        [raw_source, &packets_handled](RawPacket) {
            ++packets_handled;
            raw_source->stop();
        },
        [&completion_promise](StopReason reason) {
            completion_promise.set_value(reason);
        });

    ASSERT_TRUE(started);

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(completion_future.get(), StopReason::StoppedByUser);
    EXPECT_EQ(packets_handled, 1u);
    EXPECT_FALSE(source->is_running());
}

TEST(PacketSourceContractTest, ExceptionInCallbackHandledGracefully) {
    const std::vector<RawPacket> input = {make_test_packet(1)};

    std::unique_ptr<IPacketSource> source =
        std::make_unique<FakePacketSource>(input, LinkType::Ethernet);

    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();

    const bool started = source->start(
        [](RawPacket) {
            throw std::runtime_error("Simulated consumer failure");
        },
        [&completion_promise](StopReason reason) {
            completion_promise.set_value(reason);
        });

    ASSERT_TRUE(started);

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(completion_future.get(), StopReason::Error);
    EXPECT_FALSE(source->is_running());
    EXPECT_FALSE(source->last_error().empty());
}

TEST(PacketSourceContractTest, ValidationAndSinglePassLifecycle) {
    std::unique_ptr<IPacketSource> source =
        std::make_unique<FakePacketSource>(std::vector<RawPacket>{}, LinkType::Ethernet);

    EXPECT_FALSE(source->start(nullptr, [](StopReason) {}));
    EXPECT_FALSE(source->start([](RawPacket) {}, nullptr));

    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();

    ASSERT_TRUE(source->start([](RawPacket) {},
                              [&completion_promise](StopReason reason) {
                                  completion_promise.set_value(reason);
                              }));

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);

    EXPECT_FALSE(source->start([](RawPacket) {}, [](StopReason) {}));
}