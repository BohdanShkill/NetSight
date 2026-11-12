#pragma once

#include "netsight/analytics/DistributedAggregator.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace netsight {

class IntervalTracker {
public:
    explicit IntervalTracker(std::size_t max_agents = 64);
    ~IntervalTracker() = default;

    void annotate(std::vector<AgentMetricsReport>& reports);
    void reset() noexcept;

    [[nodiscard]] std::size_t tracked_agents() const noexcept;
    [[nodiscard]] std::size_t rejected_agents() const noexcept;
    [[nodiscard]] std::size_t max_agents() const noexcept;

private:
    struct AgentState {
        bool first_observation{true};
        double duration_seconds{0.0};
        std::uint64_t total_packets{0};
        std::uint64_t total_wire_bytes{0};
        std::uint64_t tcp_packets{0};
        std::uint64_t udp_packets{0};
        std::uint64_t icmp_packets{0};
        std::uint64_t other_packets{0};
        std::map<std::uint16_t, std::uint64_t> port_packets{};
    };

    std::size_t max_agents_{64};
    std::size_t rejected_agents_{0};
    std::map<std::string, AgentState> states_{};
};

}