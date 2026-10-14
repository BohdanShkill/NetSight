#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "netsight/core/Types.hpp"
#include "netsight/source/ThreadedPacketSource.hpp"

namespace netsight {

class FakePacketSource final : public ThreadedPacketSource {
private:
    std::vector<RawPacket> packets_;
    LinkType link_type_;
    std::optional<std::size_t> fail_after_n_;
    bool block_until_stopped_{false};

public:
    FakePacketSource(
        std::vector<RawPacket> packets,
        LinkType link_type,
        std::optional<std::size_t> fail_after_n = std::nullopt,
        bool block_until_stopped = false)
        : packets_(std::move(packets)),
          link_type_(link_type),
          fail_after_n_(fail_after_n),
          block_until_stopped_(block_until_stopped) {}

    ~FakePacketSource() override {
        stop(); 
    }

    LinkType link_type() const override {
        return link_type_;
    }

protected:
    StopReason run(PacketCallback on_packet) override {
        std::size_t dispatched = 0;

        for (const auto& pkt : packets_) {
            if (stop_requested()) {
                return StopReason::StoppedByUser;
            }

            if (fail_after_n_ && dispatched >= *fail_after_n_) {
                set_error("Simulated failure threshold reached");
                return StopReason::Error;
            }

            on_packet(pkt);
            ++dispatched;
        }

        if (block_until_stopped_) {
            while (!stop_requested()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            return StopReason::StoppedByUser;
        }

        if (stop_requested()) {
            return StopReason::StoppedByUser;
        }

        return StopReason::EndOfStream;
    }
};

}