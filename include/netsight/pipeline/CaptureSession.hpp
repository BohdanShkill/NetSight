#pragma once

#include "netsight/concurrency/BoundedQueue.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/parser/PacketParser.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include "netsight/pipeline/PacketFilter.hpp"
#include "netsight/source/IPacketSource.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace netsight {

enum class OverflowPolicy {
    DropNewest,
    Block
};

struct SessionConfig {
    std::size_t queue_capacity{8192};
    OverflowPolicy overflow{OverflowPolicy::DropNewest};
    PacketFilter filter{};
};

struct SessionCounters {
    std::uint64_t received{0};
    std::uint64_t dropped{0};
    std::uint64_t processed{0};
    std::uint64_t delivered{0};
};

using PacketSink = std::function<void(const ParsedPacket&)>;

class CaptureSession {
public:
    CaptureSession(std::unique_ptr<IPacketSource> source, SessionConfig cfg, PacketSink sink);
    ~CaptureSession();

    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;
    CaptureSession(CaptureSession&&) = delete;
    CaptureSession& operator=(CaptureSession&&) = delete;

    [[nodiscard]] bool start();
    void stop();
    [[nodiscard]] bool wait_for(std::chrono::milliseconds timeout);

    [[nodiscard]] StopReason stop_reason() const;
    [[nodiscard]] SessionCounters counters() const noexcept;
    [[nodiscard]] std::string last_error() const;

private:
    void worker_loop();
    void record_worker_error(const std::string& err);

    std::unique_ptr<IPacketSource> source_;
    SessionConfig cfg_;
    PacketSink sink_;
    LinkType link_{LinkType::Unknown};

    std::optional<BoundedQueue<RawPacket>> queue_;

    std::atomic<std::uint64_t> received_{0};
    std::atomic<std::uint64_t> processed_{0};
    std::atomic<std::uint64_t> delivered_{0};

    std::atomic<StopReason> source_reason_{StopReason::EndOfStream};

    mutable std::mutex error_mutex_;
    std::string last_error_;
    std::atomic<bool> worker_failed_{false};

    mutable std::mutex done_mutex_;
    std::condition_variable done_cv_;
    bool done_{false};

    std::thread worker_;

    mutable std::mutex lifecycle_mutex_;
    bool started_{false};
    bool stopped_{false};
};

}