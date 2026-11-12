#include "netsight/analytics/IntervalTracker.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace netsight {

IntervalTracker::IntervalTracker(std::size_t max_agents)
    : max_agents_(max_agents == 0 ? 1 : max_agents) {}

void IntervalTracker::reset() noexcept {
    states_.clear();
    rejected_agents_ = 0;
}

std::size_t IntervalTracker::tracked_agents() const noexcept {
    return states_.size();
}

std::size_t IntervalTracker::rejected_agents() const noexcept {
    return rejected_agents_;
}

std::size_t IntervalTracker::max_agents() const noexcept {
    return max_agents_;
}

void IntervalTracker::annotate(std::vector<AgentMetricsReport>& reports) {
    for (auto& report : reports) {
        if (!report.online) {
            continue;
        }

        if (std::isnan(report.capture_duration_seconds) ||
            std::isinf(report.capture_duration_seconds) ||
            report.capture_duration_seconds < 0.0) {
            report.interval.valid = false;
            continue;
        }

        auto it = states_.find(report.agent_id);
        if (it == states_.end()) {
            if (states_.size() >= max_agents_) {
                report.interval.valid = false;
                ++rejected_agents_;
                continue;
            }
            AgentState fresh_baseline{};
            it = states_.emplace(report.agent_id, fresh_baseline).first;
        }

        AgentState& prev = it->second;
        bool counter_reset = false;

        if (report.total_packets < prev.total_packets ||
            report.total_wire_bytes < prev.total_wire_bytes ||
            report.tcp_packets < prev.tcp_packets ||
            report.udp_packets < prev.udp_packets ||
            report.icmp_packets < prev.icmp_packets ||
            report.other_packets < prev.other_packets ||
            report.capture_duration_seconds < prev.duration_seconds) {
            prev = AgentState{};
            counter_reset = true;
        }

        const double dt = report.capture_duration_seconds - prev.duration_seconds;
        const std::uint64_t d_packets = report.total_packets - prev.total_packets;
        const std::uint64_t d_bytes = report.total_wire_bytes - prev.total_wire_bytes;
        const std::uint64_t d_tcp = report.tcp_packets - prev.tcp_packets;
        const std::uint64_t d_udp = report.udp_packets - prev.udp_packets;
        const std::uint64_t d_icmp = report.icmp_packets - prev.icmp_packets;
        const std::uint64_t d_other = report.other_packets - prev.other_packets;

        report.interval.counter_reset = counter_reset;

        if (dt <= 0.0) {
            if (d_packets == 0) {
                report.interval.valid = true;
                report.interval.seconds = 0.0;
                report.interval.packets = 0;
                report.interval.wire_bytes = 0;
                report.interval.tcp = 0;
                report.interval.udp = 0;
                report.interval.icmp = 0;
                report.interval.other = 0;
                report.interval.pps = 0.0;
                report.interval.bps = 0.0;
            } else {
                report.interval.valid = false;
            }
        } else {
            report.interval.valid = true;
            report.interval.seconds = dt;
            report.interval.packets = d_packets;
            report.interval.wire_bytes = d_bytes;
            report.interval.tcp = d_tcp;
            report.interval.udp = d_udp;
            report.interval.icmp = d_icmp;
            report.interval.other = d_other;
            report.interval.pps = static_cast<double>(d_packets) / dt;
            report.interval.bps = static_cast<double>(d_bytes) / dt;
        }

        report.interval.port_deltas.clear();
        for (const auto& port_entry : report.top_ports) {
            std::uint64_t delta = 0;
            if (prev.first_observation || counter_reset) {
                delta = port_entry.packets;
            } else {
                const auto port_it = prev.port_packets.find(port_entry.port);
                if (port_it != prev.port_packets.end() && port_entry.packets >= port_it->second) {
                    delta = port_entry.packets - port_it->second;
                }
            }

            if (delta > 0) {
                PortEntry entry{};
                entry.port = port_entry.port;
                entry.packets = delta;
                entry.bytes = 0;
                report.interval.port_deltas.push_back(entry);
            }
        }

        prev.first_observation = false;
        prev.duration_seconds = report.capture_duration_seconds;
        prev.total_packets = report.total_packets;
        prev.total_wire_bytes = report.total_wire_bytes;
        prev.tcp_packets = report.tcp_packets;
        prev.udp_packets = report.udp_packets;
        prev.icmp_packets = report.icmp_packets;
        prev.other_packets = report.other_packets;

        prev.port_packets.clear();
        std::size_t port_count = 0;
        for (const auto& p : report.top_ports) {
            if (port_count >= 64) {
                break;
            }
            prev.port_packets[p.port] = p.packets;
            ++port_count;
        }
    }
}

}