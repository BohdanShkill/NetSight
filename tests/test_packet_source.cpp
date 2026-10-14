#include <gtest/gtest.h>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "netsight/core/Types.hpp"
#include "netsight/source/IPacketSource.hpp"
#include "netsight/source/PcapFileReader.hpp"
#include "support/FakePacketSource.hpp"
#include "support/PcapWriter.hpp"
#include "support/TempFile.hpp"

using namespace netsight;
using namespace netsight::test;
using namespace std::chrono_literals;

namespace {

RawPacket make_test_packet(std::uint8_t id) {
    const std::vector<Byte> bytes = {id, 0xAA, 0xBB};
    return RawPacket(Timestamp{static_cast<std::int64_t>(id) * 1000}, bytes.data(), bytes.size(), static_cast<std::uint32_t>(bytes.size()));
}

using SourceFactory = std::function<std::unique_ptr<IPacketSource>(const std::vector<RawPacket>&, TempFile&)>;

struct SourceTestParam {
    std::string name;
    SourceFactory factory;
};

} 

class PacketSourceContractTest : public ::testing::TestWithParam<SourceTestParam> {
protected:
    TempFile temp_file_;

    std::unique_ptr<IPacketSource> make_source(const std::vector<RawPacket>& packets) {
        return GetParam().factory(packets, temp_file_);
    }
};

TEST_P(PacketSourceContractTest, OrderedDeliveryAndCompletion) {
    const std::vector<RawPacket> input = {
        make_test_packet(1),
        make_test_packet(2),
        make_test_packet(3)
    };

    auto source = make_source(input);
    ASSERT_NE(source, nullptr);

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

    source->stop();
    EXPECT_FALSE(source->is_running());
}

TEST_P(PacketSourceContractTest, StopInsideCallbackDeadlockImmunity) {
    const std::vector<RawPacket> input = {
        make_test_packet(1),
        make_test_packet(2),
        make_test_packet(3)
    };

    auto source = make_source(input);
    ASSERT_NE(source, nullptr);
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

    source->stop();
    EXPECT_FALSE(source->is_running());
}

TEST_P(PacketSourceContractTest, ExceptionInCallbackHandledGracefully) {
    const std::vector<RawPacket> input = {make_test_packet(1)};

    auto source = make_source(input);
    ASSERT_NE(source, nullptr);

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

    source->stop();
    EXPECT_FALSE(source->is_running());
    EXPECT_FALSE(source->last_error().empty());
}

TEST_P(PacketSourceContractTest, ValidationAndSinglePassLifecycle) {
    auto source = make_source({});
    ASSERT_NE(source, nullptr);

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

TEST_P(PacketSourceContractTest, StopAfterCompletionIsNoop) {
    auto source = make_source({make_test_packet(1)});
    ASSERT_NE(source, nullptr);

    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();

    ASSERT_TRUE(source->start([](RawPacket) {},
                              [&completion_promise](StopReason reason) {
                                  completion_promise.set_value(reason);
                              }));

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(completion_future.get(), StopReason::EndOfStream);

    source->stop();
    source->stop();
    EXPECT_FALSE(source->is_running());
}

INSTANTIATE_TEST_SUITE_P(
    Implementations,
    PacketSourceContractTest,
    ::testing::Values(
        SourceTestParam{
            "FakePacketSource",
            [](const std::vector<RawPacket>& packets, TempFile&) -> std::unique_ptr<IPacketSource> {
                return std::make_unique<FakePacketSource>(packets, LinkType::Ethernet);
            }
        },
        SourceTestParam{
            "PcapFileReader",
            [](const std::vector<RawPacket>& packets, TempFile& tf) -> std::unique_ptr<IPacketSource> {
                if (!write_pcap(tf.path(), LinkType::Ethernet, packets)) {
                    return nullptr;
                }
                std::string err;
                return PcapFileReader::open(tf.path(), err);
            }
        }
    ),
    [](const ::testing::TestParamInfo<SourceTestParam>& info) {
        return info.param.name;
    }
);

TEST(PacketSourceFakeOnlyTest, IdempotentStop) {
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

TEST(PacketSourceFakeOnlyTest, IsRunningTrueUntilCompletion) {
    const std::vector<RawPacket> input = {
        make_test_packet(1),
        make_test_packet(2)
    };

    auto source = std::make_unique<FakePacketSource>(input, LinkType::Ethernet);
    IPacketSource* raw_source = source.get();

    std::promise<StopReason> completion_promise;
    auto completion_future = completion_promise.get_future();

    bool was_running_during_completion = false;

    const bool started = source->start(
        [raw_source](RawPacket) {
            raw_source->stop();
        },
        [raw_source, &was_running_during_completion, &completion_promise](StopReason reason) {
            was_running_during_completion = raw_source->is_running();
            completion_promise.set_value(reason);
        });

    ASSERT_TRUE(started);

    ASSERT_EQ(completion_future.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(completion_future.get(), StopReason::StoppedByUser);
    EXPECT_TRUE(was_running_during_completion);

    source->stop();
    EXPECT_FALSE(source->is_running());
}