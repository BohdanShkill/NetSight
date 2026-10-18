#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace netsight {

enum class PushResult {
    Pushed,
    Dropped,
    Closed
};

template <typename T>
class BoundedQueue {
    static_assert(std::is_nothrow_move_constructible_v<T>,
                  "T must be nothrow move constructible");

public:
    explicit BoundedQueue(std::size_t capacity)
        : capacity_(capacity) {
        if (capacity == 0) {
            throw std::invalid_argument("Capacity must be greater than zero");
        }
    }

    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;
    BoundedQueue(BoundedQueue&&) = delete;
    BoundedQueue& operator=(BoundedQueue&&) = delete;
    ~BoundedQueue() = default;

    PushResult try_push(T&& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (closed_) {
            return PushResult::Closed;
        }
        if (items_.size() >= capacity_) {
            ++dropped_;
            return PushResult::Dropped;
        }

        items_.push_back(std::move(item));
        lock.unlock();
        not_empty_.notify_one();
        return PushResult::Pushed;
    }

    PushResult push(T&& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] {
            return closed_ || items_.size() < capacity_;
        });

        if (closed_) {
            return PushResult::Closed;
        }

        items_.push_back(std::move(item));
        lock.unlock();
        not_empty_.notify_one();
        return PushResult::Pushed;
    }

    std::optional<T> pop_for(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait_for(lock, timeout, [this] {
            return closed_ || !items_.empty();
        });

        if (items_.empty()) {
            return std::nullopt;
        }

        T item = std::move(items_.front());
        items_.pop_front();
        lock.unlock();

        not_full_.notify_one();
        return item;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    bool is_drained() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_ && items_.empty();
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return items_.size();
    }

    std::size_t capacity() const noexcept {
        return capacity_;
    }

    std::uint64_t dropped() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dropped_;
    }

private:
    const std::size_t capacity_;
    std::deque<T> items_;
    bool closed_{false};
    std::uint64_t dropped_{0};

    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
};
}