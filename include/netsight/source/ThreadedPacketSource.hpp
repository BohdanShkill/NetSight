#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

#include "netsight/source/IPacketSource.hpp"

namespace netsight {
class ThreadedPacketSource : public IPacketSource {

    private:
    void run_worker(PacketCallback on_packet, CompletionCallback on_complete);
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> finished_{false};
    std::thread worker_thread_;
    std::mutex lifecycle_mutex_;          
    mutable std::mutex error_mutex_;      
    std::string last_error_;

    public:
    ~ThreadedPacketSource() override;
    bool start(PacketCallback on_packet, CompletionCallback on_complete) final;
    void stop() final;
    bool is_running() const final;
    std::string last_error() const final;
    
    protected:
    ThreadedPacketSource() = default;

    virtual StopReason run(PacketCallback on_packet) = 0;
    virtual void on_stop_requested() {}
    bool stop_requested() const noexcept {
        return stop_requested_.load();
    }
    void set_error(std::string msg);
};
}