#include "netsight/pipeline/CaptureSession.hpp"

#include <utility>

namespace netsight {

CaptureSession::CaptureSession(std::unique_ptr<IPacketSource> source, SessionConfig cfg, PacketSink sink)
    : source_(std::move(source)),
      cfg_(std::move(cfg)),
      sink_(std::move(sink)) {}

CaptureSession::~CaptureSession() {
    stop();
}

void CaptureSession::record_worker_error(const std::string& err) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = err;
    worker_failed_.store(true, std::memory_order_relaxed);
}

bool CaptureSession::start() {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);

    if (started_) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "session already started";
        return false;
    }

    if (!source_) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "source is null";
        return false;
    }

    if (!sink_) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "sink must not be empty";
        return false;
    }

    if (cfg_.queue_capacity < 1 || cfg_.queue_capacity > 1048576) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "queue capacity must be in range [1, 1048576]";
        return false;
    }

    if (cfg_.filter.port.has_value() && *cfg_.filter.port == 0) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "filter port must be 1..65535";
        return false;
    }

    if (cfg_.filter.ip.has_value() && !cfg_.filter.ip->is_valid()) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "filter ip is invalid";
        return false;
    }

    if (cfg_.tick_interval.count() <= 0) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "tick interval must be > 0";
        return false;
    }

    if (source_->link_type() == LinkType::Unknown) {
        std::lock_guard<std::mutex> err_lock(error_mutex_);
        last_error_ = "unsupported link type";
        return false;
    }

    link_ = source_->link_type();
    queue_.emplace(cfg_.queue_capacity);
    started_ = true;

    worker_ = std::thread(&CaptureSession::worker_loop, this);

    const bool ok = source_->start(
        [this](RawPacket pkt) {
            received_.fetch_add(1, std::memory_order_relaxed);
            if (cfg_.overflow == OverflowPolicy::DropNewest) {
                queue_->try_push(std::move(pkt));
            } else {
                queue_->push(std::move(pkt));
            }
        },
        [this](StopReason r) {
         source_reason_.store(r, std::memory_order_relaxed);
         if (r == StopReason::Error && source_) {
             std::lock_guard<std::mutex> err_lock(error_mutex_);
             if (last_error_.empty()) {
                 last_error_ = source_->last_error();
             }
         }
         queue_->close();
        }
    );

    if (!ok) {
        {
            std::lock_guard<std::mutex> err_lock(error_mutex_);
            last_error_ = "source failed to start: " + source_->last_error();
        }
        queue_->close();
        if (worker_.joinable()) {
            worker_.join();
        }
        return false;
    }

    return true;
}

void CaptureSession::worker_loop() {
    try {
        const auto wait_slice = std::min(std::chrono::milliseconds(100), cfg_.tick_interval);
        auto next_tick = std::chrono::steady_clock::now() + cfg_.tick_interval;

        while (true) {
            auto item = queue_->pop_for(wait_slice);
            if (!item.has_value()) {
                if (queue_->is_drained()) {
                    break;
                }
                if (cfg_.on_tick && std::chrono::steady_clock::now() >= next_tick) {
                    cfg_.on_tick();
                    next_tick = std::chrono::steady_clock::now() + cfg_.tick_interval;
                }
                continue;
            }

            auto parsed = parse_packet(*item, link_);
            const auto new_processed = processed_.fetch_add(1, std::memory_order_relaxed) + 1;

            if (cfg_.filter.matches(parsed)) {
                sink_(parsed);
                delivered_.fetch_add(1, std::memory_order_relaxed);
            }

            if (cfg_.on_tick && (new_processed & 0x3FFu) == 0) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= next_tick) {
                    cfg_.on_tick();
                    next_tick = now + cfg_.tick_interval;
                }
            }
        }

        if (cfg_.on_tick) {
            cfg_.on_tick();
        }
    } catch (const std::exception& e) {
        record_worker_error(std::string("sink threw: ") + e.what());
        queue_->close();
    } catch (...) {
        record_worker_error("sink threw unknown exception");
        queue_->close();
    }

    {
        std::lock_guard<std::mutex> lock(done_mutex_);
        done_ = true;
    }
    done_cv_.notify_all();
}

void CaptureSession::stop() {
    if (worker_.get_id() == std::this_thread::get_id()) {
        if (queue_) {
            queue_->close();
        }
        return;
    }

    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    if (!started_ || stopped_) {
        return;
    }

    if (source_) {
        source_->stop();
    }
    if (queue_) {
        queue_->close();
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    stopped_ = true;
}

bool CaptureSession::wait_for(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(done_mutex_);
    return done_cv_.wait_for(lock, timeout, [this] { return done_; });
}

StopReason CaptureSession::stop_reason() const {
    if (worker_failed_.load(std::memory_order_relaxed)) {
        return StopReason::Error;
    }
    return source_reason_.load(std::memory_order_relaxed);
}

SessionCounters CaptureSession::counters() const noexcept {
    SessionCounters c;
    c.received = received_.load(std::memory_order_relaxed);
    c.dropped = queue_ ? queue_->dropped() : 0;
    c.processed = processed_.load(std::memory_order_relaxed);
    c.delivered = delivered_.load(std::memory_order_relaxed);
    return c;
}

std::string CaptureSession::last_error() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    if (!last_error_.empty()) {
        return last_error_;
    }
    if (source_ && source_reason_.load(std::memory_order_relaxed) == StopReason::Error) {
        return source_->last_error();
    }
    return "";
}

}