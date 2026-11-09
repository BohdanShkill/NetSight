#pragma once

#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/parser/ParsedPacket.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace netsight {

struct StatsConfig {
    std::size_t top_n{10};
    std::size_t max_tracked_talkers{4096};
    std::size_t max_tracked_ports{1024};
};

class StatsAggregator {
public:
    explicit StatsAggregator(StatsConfig cfg = {});
    ~StatsAggregator() = default;

    StatsAggregator(const StatsAggregator&) = delete;
    StatsAggregator& operator=(const StatsAggregator&) = delete;
    StatsAggregator(StatsAggregator&&) = delete;
    StatsAggregator& operator=(StatsAggregator&&) = delete;

    void record(const ParsedPacket& pkt);

    [[nodiscard]] StatsSnapshot build_snapshot(const DropCounters& external_drops = {}) const;

    std::shared_ptr<const StatsSnapshot> publish(const DropCounters& external_drops = {},
                                                 std::vector<Alert> alerts = {},
                                                 std::vector<SynTargetEntry> syn_targets = {});

    [[nodiscard]] std::shared_ptr<const StatsSnapshot> latest_snapshot() const noexcept;

    [[nodiscard]] std::size_t tracked_talker_count() const noexcept;
    [[nodiscard]] std::size_t tracked_port_count() const noexcept;

    void reset();

private:
    StatsConfig cfg_{};

    std::uint64_t total_packets_{0};
    std::uint64_t total_wire_bytes_{0};
    std::uint64_t total_captured_bytes_{0};

    Timestamp first_packet_ts_{0};
    Timestamp last_packet_ts_{0};

    ParseStatusCounts status_{};
    NetworkProtocolCounts l3_{};
    TransportProtocolCounts l4_{};

    std::unordered_map<IpAddress, TrafficCounter> talkers_{};
    std::unordered_map<std::uint16_t, TrafficCounter> ports_{};

    std::uint64_t untracked_talker_packets_{0};
    std::uint64_t untracked_port_packets_{0};

    std::uint64_t seq_{0};

    mutable std::mutex snapshot_mutex_{};
    std::shared_ptr<const StatsSnapshot> published_{};
};

}