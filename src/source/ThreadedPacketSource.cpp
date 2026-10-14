#include "netsight/source/ThreadedPacketSource.hpp"

#include <cassert>
#include <exception>
#include <utility>

namespace netsight {

bool ThreadedPacketSource::start(PacketCallback on_packet, CompletionCallback on_complete) {

    std::lock_guard<std::mutex> lock(lifecycle_mutex_);

    if (!on_packet || !on_complete) {
        set_error("Callbacks must not be empty");
        return false;
    }

    if (finished_.load()) {
        set_error("Source has already finished; cannot restart");
        return false;
    }

    if (running_.load()) {
        set_error("Source is already running");
        return false;
    }

    stop_requested_.store(false);
    running_.store(true);

    worker_thread_ = std::thread([this, 
                                  pkt = std::move(on_packet), 
                                  comp = std::move(on_complete)]() mutable {
        run_worker(std::move(pkt), std::move(comp));
    });

    return true;
}

void ThreadedPacketSource::stop() {
    stop_requested_.store(true);

    on_stop_requested();

    if (worker_thread_.get_id() == std::this_thread::get_id()) {
        return;
    }

    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void ThreadedPacketSource::run_worker(PacketCallback on_packet, CompletionCallback on_complete) {
    StopReason reason = StopReason::EndOfStream;

    try {
        reason = run(on_packet);
    } catch (const std::exception& e) {
        set_error(std::string("packet callback threw: ") + e.what());
        reason = StopReason::Error;
    } catch (...) {
        set_error("packet callback threw unknown exception");
        reason = StopReason::Error;
    }

    finished_.store(true);

    try {
        on_complete(reason);
    } catch (...) {
        set_error("Exception escaped from completion callback");
    }

    running_.store(false);
}

ThreadedPacketSource::~ThreadedPacketSource() {
    assert(!worker_thread_.joinable() && "Derived class must call stop() in its destructor!");
}

bool ThreadedPacketSource::is_running() const {
    return running_.load();
}

std::string ThreadedPacketSource::last_error() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

void ThreadedPacketSource::set_error(std::string msg) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = std::move(msg);
}

} 