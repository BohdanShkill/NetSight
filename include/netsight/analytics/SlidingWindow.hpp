#pragma once

#include "netsight/core/Types.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace netsight {

template <std::size_t NumBuckets = 10>
class SlidingWindow {
    static_assert(NumBuckets > 0, "NumBuckets must be > 0");

public:
    static constexpr std::size_t kNumBuckets = NumBuckets;

    explicit SlidingWindow(Timestamp window_duration = Timestamp{1'000'000}) noexcept {
        const std::int64_t duration_us = window_duration.count();
        bucket_us_ = std::max<std::int64_t>(1, duration_us / static_cast<std::int64_t>(NumBuckets));
        window_duration_ = Timestamp{bucket_us_ * static_cast<std::int64_t>(NumBuckets)};
    }

    void advance(Timestamp now) noexcept {
        if (now.count() < 0) {
            return;
        }

        const auto tick = now.count() / bucket_us_;
        if (!initialized_) {
            initialized_ = true;
            current_bucket_tick_ = tick;
            head_index_ = 0;
            return;
        }

        if (tick <= current_bucket_tick_) {
            return;
        }

        const auto delta = static_cast<std::size_t>(tick - current_bucket_tick_);
        if (delta >= NumBuckets) {
            buckets_.fill(0);
            total_ = 0;
            head_index_ = (head_index_ + delta) % NumBuckets;
            current_bucket_tick_ = tick;
            return;
        }

        for (std::size_t i = 0; i < delta; ++i) {
            head_index_ = (head_index_ + 1) % NumBuckets;
            total_ -= buckets_[head_index_];
            buckets_[head_index_] = 0;
        }
        current_bucket_tick_ = tick;
    }

    void add(Timestamp ts, std::uint64_t count = 1) noexcept {
        if (count == 0 || ts.count() < 0) {
            return;
        }

        const auto tick = ts.count() / bucket_us_;
        if (!initialized_ || tick >= current_bucket_tick_) {
            advance(ts);
            buckets_[head_index_] += count;
            total_ += count;
            return;
        }

        const auto age = static_cast<std::size_t>(current_bucket_tick_ - tick);
        if (age >= NumBuckets) {
            return;
        }

        const std::size_t idx = (head_index_ + NumBuckets - age) % NumBuckets;
        buckets_[idx] += count;
        total_ += count;
    }

    [[nodiscard]] std::uint64_t total() const noexcept {
        return total_;
    }

    [[nodiscard]] std::uint64_t total(Timestamp now) noexcept {
        advance(now);
        return total_;
    }

    [[nodiscard]] double rate_per_second() const noexcept {
        if (window_duration_.count() <= 0) {
            return 0.0;
        }
        return static_cast<double>(total_) * 1'000'000.0 / static_cast<double>(window_duration_.count());
    }

    [[nodiscard]] Timestamp window_duration() const noexcept {
        return window_duration_;
    }

    [[nodiscard]] Timestamp bucket_duration() const noexcept {
        return Timestamp{bucket_us_};
    }

    void reset() noexcept {
        buckets_.fill(0);
        total_ = 0;
        head_index_ = 0;
        current_bucket_tick_ = 0;
        initialized_ = false;
    }

private:
    std::array<std::uint64_t, NumBuckets> buckets_{};
    std::uint64_t total_{0};
    std::int64_t bucket_us_{100'000};
    Timestamp window_duration_{1'000'000};
    std::int64_t current_bucket_tick_{0};
    std::size_t head_index_{0};
    bool initialized_{false};
};

}