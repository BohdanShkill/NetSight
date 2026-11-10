#pragma once

#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netsight {

enum class DistributedAlertSeverity : std::uint8_t {
    Warning = 0,
    Critical = 1
};

inline std::string to_string(DistributedAlertSeverity sev) {
    switch (sev) {
        case DistributedAlertSeverity::Warning:  return "warning";
        case DistributedAlertSeverity::Critical: return "critical";
        default:                                 return "unknown";
    }
}

enum class DistributedAlertType : std::uint8_t {
    DistributedSynFlood = 0,
    DistributedVolumetricFlood = 1,
    DistributedTargetConcentration = 2
};

inline std::string to_string(DistributedAlertType type) {
    switch (type) {
        case DistributedAlertType::DistributedSynFlood:
            return "distributed_syn_flood";
        case DistributedAlertType::DistributedVolumetricFlood:
            return "distributed_volumetric_flood";
        case DistributedAlertType::DistributedTargetConcentration:
            return "distributed_target_concentration";
        default:
            return "unknown";
    }
}

struct DistributedAlert {
    DistributedAlertType type{DistributedAlertType::DistributedSynFlood};
    DistributedAlertSeverity severity{DistributedAlertSeverity::Warning};
    IpAddress target_ip{};
    std::uint16_t target_port{0};
    std::size_t contributing_agents{0};
    double combined_rate_pps{0.0};
    double metric_ratio{0.0};
    std::string description{};

    bool operator==(const DistributedAlert& rhs) const noexcept {
        return type == rhs.type &&
               severity == rhs.severity &&
               target_ip == rhs.target_ip &&
               target_port == rhs.target_port &&
               contributing_agents == rhs.contributing_agents &&
               combined_rate_pps == rhs.combined_rate_pps &&
               metric_ratio == rhs.metric_ratio &&
               description == rhs.description;
    }

    bool operator!=(const DistributedAlert& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct AgentMetricsReport {
    std::string agent_id{};
    bool online{true};
    std::string error_message{};

    std::uint64_t total_packets{0};
    std::uint64_t total_wire_bytes{0};
    double pps{0.0};
    double bps{0.0};

    std::uint64_t tcp_packets{0};
    std::uint64_t udp_packets{0};
    std::uint64_t icmp_packets{0};
    std::uint64_t other_packets{0};

    std::vector<TalkerEntry> top_talkers{};
    std::vector<PortEntry> top_ports{};
    std::vector<SynTargetEntry> syn_targets{};
    std::size_t active_alerts_count{0};
};

struct DistributedAggregatorConfig {
    std::size_t min_agents{2};
    double global_syn_pps_threshold{100.0};
    double max_syn_ack_ratio{0.25};
    double global_volumetric_pps_threshold{500.0};
    double protocol_dominance_ratio{0.70};
    double target_port_concentration_ratio{0.60};
    std::size_t top_k_limit{10};
};

struct GlobalNetworkSnapshot {
    std::size_t total_agents{0};
    std::size_t online_agents{0};
    std::uint64_t total_packets{0};
    std::uint64_t total_wire_bytes{0};
    double global_pps{0.0};
    double global_bps{0.0};

    std::uint64_t tcp_packets{0};
    std::uint64_t udp_packets{0};
    std::uint64_t icmp_packets{0};
    std::uint64_t other_packets{0};

    std::vector<TalkerEntry> merged_top_talkers{};
    std::vector<PortEntry> merged_top_ports{};
    std::vector<SynTargetEntry> merged_syn_targets{};
    std::vector<DistributedAlert> alerts{};
};

class DistributedAggregator {
public:
    explicit DistributedAggregator(DistributedAggregatorConfig cfg = {});
    ~DistributedAggregator() = default;

    [[nodiscard]] GlobalNetworkSnapshot aggregate(const std::vector<AgentMetricsReport>& reports) const;
    [[nodiscard]] GlobalNetworkSnapshot evaluate_round(const std::vector<AgentMetricsReport>& reports) const;

    [[nodiscard]] const DistributedAggregatorConfig& config() const noexcept { return cfg_; }

private:
    DistributedAggregatorConfig cfg_;
};

}