#pragma once

#include "netsight/analytics/Alert.hpp"
#include "netsight/analytics/SlidingWindow.hpp"
#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/parser/ParsedPacket.hpp"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace netsight {

struct EndpointKey {
    IpAddress ip{};
    std::uint16_t port{0};

    bool operator==(const EndpointKey& rhs) const noexcept {
        return ip == rhs.ip && port == rhs.port;
    }

    bool operator<(const EndpointKey& rhs) const noexcept {
        if (ip < rhs.ip) return true;
        if (rhs.ip < ip) return false;
        return port < rhs.port;
    }
};

struct EndpointKeyHash {
    std::size_t operator()(const EndpointKey& k) const noexcept {
        std::size_t h = std::hash<IpAddress>{}(k.ip);
        h ^= std::hash<std::uint16_t>{}(k.port) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};

struct SynFloodConfig {
    Timestamp window_duration{1'000'000};
    std::uint64_t syn_threshold{100};
    std::uint64_t recovery_syn_threshold{30};
    double max_syn_ack_ratio{0.25};
    Timestamp entry_ttl{10'000'000};
    std::size_t max_tracked_targets{4096};
    std::size_t max_alerts{256};
};

class SynFloodDetector {
public:
    explicit SynFloodDetector(SynFloodConfig cfg = {});
    ~SynFloodDetector() = default;

    SynFloodDetector(const SynFloodDetector&) = delete;
    SynFloodDetector& operator=(const SynFloodDetector&) = delete;
    SynFloodDetector(SynFloodDetector&&) = delete;
    SynFloodDetector& operator=(SynFloodDetector&&) = delete;

    void record(const ParsedPacket& pkt);

    void on_tick(Timestamp now = Timestamp{0});

    [[nodiscard]] const std::vector<Alert>& alerts() const noexcept;
    [[nodiscard]] std::vector<Alert> active_alerts() const;
    [[nodiscard]] std::size_t tracked_target_count() const noexcept;
    [[nodiscard]] std::uint64_t untracked_target_packets() const noexcept;
    [[nodiscard]] std::vector<SynTargetEntry> top_targets(std::size_t limit = 16) const;
    void reset();

private:
    struct TargetState {
        SlidingWindow<10> syn_window;
        SlidingWindow<10> syn_ack_window;
        Timestamp last_seen{0};
        std::uint64_t active_alert_id{0};

        explicit TargetState(Timestamp window_duration)
            : syn_window(window_duration), syn_ack_window(window_duration) {}
    };

    void evaluate_target(const EndpointKey& key, TargetState& target, Timestamp ts);
    void evict_expired(Timestamp effective_now);

    SynFloodConfig cfg_;
    std::unordered_map<EndpointKey, TargetState, EndpointKeyHash> targets_;
    AlertLog log_;
    std::uint64_t untracked_target_packets_{0};
    Timestamp max_seen_ts_{0};
};

}