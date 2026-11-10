#include "netsight/analytics/DistributedAggregator.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>

namespace netsight {

namespace {

struct SynTargetKey {
    IpAddress ip{};
    std::uint16_t port{0};

    bool operator==(const SynTargetKey& rhs) const noexcept {
        return ip == rhs.ip && port == rhs.port;
    }

    bool operator<(const SynTargetKey& rhs) const noexcept {
        if (ip != rhs.ip) {
            return ip < rhs.ip;
        }
        return port < rhs.port;
    }
};

struct SynAggData {
    std::uint64_t syn_count{0};
    std::uint64_t syn_ack_count{0};
    double syn_rate_pps{0.0};
    std::size_t witness_count{0};
};

struct PortAggData {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::size_t witness_count{0};
};

}

DistributedAggregator::DistributedAggregator(DistributedAggregatorConfig cfg)
    : cfg_(cfg) {
    if (cfg_.min_agents == 0) {
        cfg_.min_agents = 1;
    }
    if (cfg_.top_k_limit == 0) {
        cfg_.top_k_limit = 1;
    }
}

GlobalNetworkSnapshot DistributedAggregator::evaluate_round(const std::vector<AgentMetricsReport>& reports) const {
    return aggregate(reports);
}

GlobalNetworkSnapshot DistributedAggregator::aggregate(const std::vector<AgentMetricsReport>& reports) const {
    GlobalNetworkSnapshot snap{};
    snap.total_agents = reports.size();

    if (reports.empty()) {
        return snap;
    }

    std::map<IpAddress, TrafficCounter> talker_map;
    std::map<std::uint16_t, PortAggData> port_map;
    std::map<SynTargetKey, SynAggData> syn_map;

    std::size_t udp_witnesses = 0;
    std::size_t icmp_witnesses = 0;

    for (const auto& r : reports) {
        if (!r.online) {
            continue;
        }

        ++snap.online_agents;
        snap.total_packets += r.total_packets;
        snap.total_wire_bytes += r.total_wire_bytes;
        snap.global_pps += r.pps;
        snap.global_bps += r.bps;

        snap.tcp_packets += r.tcp_packets;
        snap.udp_packets += r.udp_packets;
        snap.icmp_packets += r.icmp_packets;
        snap.other_packets += r.other_packets;

        if (r.udp_packets > 0) {
            ++udp_witnesses;
        }
        if (r.icmp_packets > 0) {
            ++icmp_witnesses;
        }

        for (const auto& t : r.top_talkers) {
            auto& val = talker_map[t.ip];
            val.packets += t.packets;
            val.bytes += t.bytes;
        }

        for (const auto& p : r.top_ports) {
            auto& val = port_map[p.port];
            val.packets += p.packets;
            val.bytes += p.bytes;
            ++val.witness_count;
        }

        for (const auto& s : r.syn_targets) {
            if (s.syn_count > 0) {
                SynTargetKey k{s.dst_ip, s.dst_port};
                auto& val = syn_map[k];
                val.syn_count += s.syn_count;
                val.syn_ack_count += s.syn_ack_count;
                val.syn_rate_pps += s.syn_rate_pps;
                ++val.witness_count;
            }
        }
    }

    if (!talker_map.empty()) {
        std::vector<TalkerEntry> entries;
        entries.reserve(talker_map.size());
        for (const auto& [ip, counter] : talker_map) {
            entries.push_back(TalkerEntry{ip, counter.packets, counter.bytes});
        }
        std::sort(entries.begin(), entries.end(), [](const TalkerEntry& a, const TalkerEntry& b) noexcept {
            if (a.bytes != b.bytes) return a.bytes > b.bytes;
            if (a.packets != b.packets) return a.packets > b.packets;
            return a.ip < b.ip;
        });
        if (entries.size() > cfg_.top_k_limit) {
            entries.resize(cfg_.top_k_limit);
        }
        snap.merged_top_talkers = std::move(entries);
    }

    if (!port_map.empty()) {
        std::vector<PortEntry> entries;
        entries.reserve(port_map.size());
        for (const auto& [port, data] : port_map) {
            entries.push_back(PortEntry{port, data.packets, data.bytes});
        }
        std::sort(entries.begin(), entries.end(), [](const PortEntry& a, const PortEntry& b) noexcept {
            if (a.bytes != b.bytes) return a.bytes > b.bytes;
            if (a.packets != b.packets) return a.packets > b.packets;
            return a.port < b.port;
        });
        if (entries.size() > cfg_.top_k_limit) {
            entries.resize(cfg_.top_k_limit);
        }
        snap.merged_top_ports = std::move(entries);
    }

    if (!syn_map.empty()) {
        std::vector<SynTargetEntry> entries;
        entries.reserve(syn_map.size());
        for (const auto& [key, data] : syn_map) {
            entries.push_back(SynTargetEntry{
                key.ip,
                key.port,
                data.syn_count,
                data.syn_ack_count,
                data.syn_rate_pps
            });
        }
        std::sort(entries.begin(), entries.end(), [](const SynTargetEntry& a, const SynTargetEntry& b) noexcept {
            if (a.syn_count != b.syn_count) return a.syn_count > b.syn_count;
            if (a.dst_ip != b.dst_ip) return a.dst_ip < b.dst_ip;
            return a.dst_port < b.dst_port;
        });
        if (entries.size() > cfg_.top_k_limit) {
            entries.resize(cfg_.top_k_limit);
        }
        snap.merged_syn_targets = std::move(entries);
    }

    for (const auto& [key, data] : syn_map) {
        const double ratio = (data.syn_count > 0)
            ? (static_cast<double>(data.syn_ack_count) / static_cast<double>(data.syn_count))
            : 0.0;

        if (data.witness_count >= cfg_.min_agents &&
            data.syn_rate_pps >= cfg_.global_syn_pps_threshold &&
            ratio <= cfg_.max_syn_ack_ratio) {

            std::ostringstream oss;
            oss << "Distributed SYN Flood on " << key.ip.to_string() << ":" << key.port
                << " observed by " << data.witness_count << " agents (rate: "
                << std::fixed << std::setprecision(1) << data.syn_rate_pps
                << " pps, ack_ratio: " << std::setprecision(3) << ratio << ")";

            DistributedAlert alert{};
            alert.type = DistributedAlertType::DistributedSynFlood;
            alert.severity = DistributedAlertSeverity::Critical;
            alert.target_ip = key.ip;
            alert.target_port = key.port;
            alert.contributing_agents = data.witness_count;
            alert.combined_rate_pps = data.syn_rate_pps;
            alert.metric_ratio = ratio;
            alert.description = oss.str();
            snap.alerts.push_back(std::move(alert));
        }
    }

    if (snap.total_packets > 0 && snap.global_pps >= cfg_.global_volumetric_pps_threshold) {
        const double udp_share = static_cast<double>(snap.udp_packets) / static_cast<double>(snap.total_packets);
        if (udp_witnesses >= cfg_.min_agents && udp_share >= cfg_.protocol_dominance_ratio) {
            std::ostringstream oss;
            oss << "Distributed Volumetric UDP Flood observed across " << udp_witnesses
                << " agents (global rate: " << std::fixed << std::setprecision(1)
                << snap.global_pps << " pps, udp_share: "
                << std::setprecision(3) << udp_share << ")";

            DistributedAlert alert{};
            alert.type = DistributedAlertType::DistributedVolumetricFlood;
            alert.severity = DistributedAlertSeverity::Critical;
            alert.target_ip = IpAddress{};
            alert.target_port = 0;
            alert.contributing_agents = udp_witnesses;
            alert.combined_rate_pps = snap.global_pps;
            alert.metric_ratio = udp_share;
            alert.description = oss.str();
            snap.alerts.push_back(std::move(alert));
        }

        const double icmp_share = static_cast<double>(snap.icmp_packets) / static_cast<double>(snap.total_packets);
        if (icmp_witnesses >= cfg_.min_agents && icmp_share >= cfg_.protocol_dominance_ratio) {
            std::ostringstream oss;
            oss << "Distributed Volumetric ICMP Flood observed across " << icmp_witnesses
                << " agents (global rate: " << std::fixed << std::setprecision(1)
                << snap.global_pps << " pps, icmp_share: "
                << std::setprecision(3) << icmp_share << ")";

            DistributedAlert alert{};
            alert.type = DistributedAlertType::DistributedVolumetricFlood;
            alert.severity = DistributedAlertSeverity::Critical;
            alert.target_ip = IpAddress{};
            alert.target_port = 0;
            alert.contributing_agents = icmp_witnesses;
            alert.combined_rate_pps = snap.global_pps;
            alert.metric_ratio = icmp_share;
            alert.description = oss.str();
            snap.alerts.push_back(std::move(alert));
        }
    }

    if (snap.total_packets > 0 && snap.global_pps >= cfg_.global_volumetric_pps_threshold) {
        for (const auto& [port, data] : port_map) {
            const double port_share = static_cast<double>(data.packets) / static_cast<double>(snap.total_packets);
            if (data.witness_count >= cfg_.min_agents && port_share >= cfg_.target_port_concentration_ratio) {
                std::ostringstream oss;
                oss << "Distributed Target Concentration on port " << port
                    << " observed by " << data.witness_count << " agents (port_share: "
                    << std::fixed << std::setprecision(3) << port_share << ")";

                DistributedAlert alert{};
                alert.type = DistributedAlertType::DistributedTargetConcentration;
                alert.severity = DistributedAlertSeverity::Warning;
                alert.target_ip = IpAddress{};
                alert.target_port = port;
                alert.contributing_agents = data.witness_count;
                alert.combined_rate_pps = snap.global_pps;
                alert.metric_ratio = port_share;
                alert.description = oss.str();
                snap.alerts.push_back(std::move(alert));
            }
        }
    }

    std::sort(snap.alerts.begin(), snap.alerts.end(), [](const DistributedAlert& a, const DistributedAlert& b) noexcept {
        if (a.type != b.type) {
            return static_cast<std::uint8_t>(a.type) < static_cast<std::uint8_t>(b.type);
        }
        if (a.target_ip != b.target_ip) {
            return a.target_ip < b.target_ip;
        }
        if (a.target_port != b.target_port) {
            return a.target_port < b.target_port;
        }
        return a.combined_rate_pps > b.combined_rate_pps;
    });

    return snap;
}

}