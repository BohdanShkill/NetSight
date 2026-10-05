#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "netsight/core/Types.hpp"
#include "netsight/source/IPacketSource.hpp"

namespace netsight {

class FakePacketSource : public IPacketSource {
private:
    std::vector<RawPacket> packets_;
    LinkType link_type_;
    std::optional<std::size_t> fail_after_n_;
    bool block_until_stopped_{false};

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> finished_{false};

    std::thread worker_thread_;
    mutable std::mutex error_mutex_;
    std::string last_error_;
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

    bool start(PacketCallback on_packet, CompletionCallback on_complete) override {
        if (!on_packet || !on_complete) {
            set_error("Callbacks must not be empty");
            return false;
        }

        if (finished_.load()) {
            set_error("Source has already finished; cannot restart");
            return false;
        }

        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) {
            set_error("Source is already running");
            return false;
        }

        stop_requested_.store(false);

        worker_thread_ = std::thread([this, 
                                      pkt_cb = std::move(on_packet), 
                                      comp_cb = std::move(on_complete)]() mutable {
            run_worker(std::move(pkt_cb), std::move(comp_cb));
        });

        return true;
    }

    void stop() override {
        stop_requested_.store(true);

        if (worker_thread_.joinable()) {
            if (std::this_thread::get_id() != worker_thread_.get_id()) {
                worker_thread_.join();
            }
        }

        running_.store(false);
    }

    bool is_running() const override {
        return running_.load();
    }

    LinkType link_type() const override {
        return link_type_;
    }

    std::string last_error() const override {
        std::lock_guard<std::mutex> lock(error_mutex_);
        return last_error_;
    }

private:
    void set_error(std::string msg) {
        std::lock_guard<std::mutex> lock(error_mutex_);
        last_error_ = std::move(msg);
    }

    void run_worker(PacketCallback on_packet, CompletionCallback on_complete) {
        StopReason reason = StopReason::EndOfStream;

        try {
            std::size_t dispatched = 0;

            for (const auto& pkt : packets_) {
                if (stop_requested_.load()) {
                    reason = StopReason::StoppedByUser;
                    break;
                }

                if (fail_after_n_ && dispatched >= *fail_after_n_) {
                    set_error("Simulated failure threshold reached");
                    reason = StopReason::Error;
                    break;
                }

                on_packet(pkt);
                ++dispatched;
            }

            if (reason == StopReason::EndOfStream && block_until_stopped_) {
                while (!stop_requested_.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                reason = StopReason::StoppedByUser;
            } else if (stop_requested_.load()) {
                reason = StopReason::StoppedByUser;
            }
        } catch (...) {
            set_error("Exception escaped from packet callback");
            reason = StopReason::Error;
        }

        running_.store(false);
        finished_.store(true);

        try {
            on_complete(reason);
        } catch (...) {
            set_error("Exception escaped from completion callback");
        }
    }
};

} 