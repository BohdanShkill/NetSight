#include "netsight/export/JsonSerializer.hpp"

#include "netsight/core/Time.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <nlohmann/json.hpp>

namespace netsight {

namespace {

using json = nlohmann::json;

double safe_double(double x) noexcept {
    return std::isfinite(x) ? x : 0.0;
}

json ip_or_null(const IpAddress& ip) {
    if (ip.is_valid()) {
        return ip.to_string();
    }
    return nullptr;
}

std::string dump_json(const json& j) {
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

}

std::optional<std::size_t> parse_limit_param(std::string_view raw, std::size_t max_limit) noexcept {
    if (raw.empty() || max_limit == 0) {
        return std::nullopt;
    }

    std::size_t val = 0;
    const char* first = raw.data();
    const char* last = raw.data() + raw.size();
    auto [ptr, ec] = std::from_chars(first, last, val);

    if (ec != std::errc{} || ptr != last) {
        return std::nullopt;
    }

    if (val < 1 || val > max_limit) {
        return std::nullopt;
    }

    return val;
}

std::optional<AlertFilterState> parse_alert_state_param(std::string_view raw) noexcept {
    if (raw == "all") {
        return AlertFilterState::All;
    }
    if (raw == "active") {
        return AlertFilterState::Active;
    }
    if (raw == "resolved") {
        return AlertFilterState::Resolved;
    }
    return std::nullopt;
}

std::string serialize_health_json(std::string_view version, std::uint64_t snapshot_seq) {
    json j = {
        {"status", "ok"},
        {"version", version},
        {"snapshot_seq", snapshot_seq}
    };
    return dump_json(j);
}

std::string serialize_stats_json(const StatsSnapshot& snap) {
    json first_pkt = nullptr;
    json last_pkt = nullptr;
    if (snap.total_packets > 0) {
        first_pkt = format_iso8601_utc(snap.first_packet_ts);
        last_pkt = format_iso8601_utc(snap.last_packet_ts);
    }

    std::size_t active_alerts_count = 0;
    for (const auto& a : snap.alerts) {
        if (a.state == AlertState::Active) {
            ++active_alerts_count;
        }
    }

    json top_ports_json = json::array();
    for (const auto& p : snap.top_ports) {
        top_ports_json.push_back({
            {"port", p.port},
            {"packets", p.packets},
            {"bytes", p.bytes}
        });
    }

    json j = {
        {"snapshot_seq", snap.snapshot_seq},
        {"totals", {
            {"packets", snap.total_packets},
            {"wire_bytes", snap.total_wire_bytes},
            {"captured_bytes", snap.total_captured_bytes},
            {"first_packet", first_pkt},
            {"last_packet", last_pkt},
            {"duration_seconds", safe_double(snap.duration_seconds)},
            {"packets_per_second", safe_double(snap.packets_per_second)},
            {"bytes_per_second", safe_double(snap.bytes_per_second)}
        }},
        {"parse", {
            {"ok", snap.status.ok},
            {"truncated", snap.status.truncated},
            {"malformed", snap.status.malformed},
            {"unsupported_link", snap.status.unsupported_link}
        }},
        {"l3", {
            {"ipv4", {{"packets", snap.l3.ipv4.packets}, {"bytes", snap.l3.ipv4.bytes}}},
            {"ipv6", {{"packets", snap.l3.ipv6.packets}, {"bytes", snap.l3.ipv6.bytes}}},
            {"arp", {{"packets", snap.l3.arp.packets}, {"bytes", snap.l3.arp.bytes}}},
            {"other", {{"packets", snap.l3.other.packets}, {"bytes", snap.l3.other.bytes}}},
            {"vlan_tagged_packets", snap.l3.vlan_tagged_packets},
            {"fragmented_packets", snap.l3.fragmented_packets}
        }},
        {"l4", {
            {"tcp", {{"packets", snap.l4.tcp.packets}, {"bytes", snap.l4.tcp.bytes}}},
            {"udp", {{"packets", snap.l4.udp.packets}, {"bytes", snap.l4.udp.bytes}}},
            {"icmp", {{"packets", snap.l4.icmp.packets}, {"bytes", snap.l4.icmp.bytes}}},
            {"icmpv6", {{"packets", snap.l4.icmpv6.packets}, {"bytes", snap.l4.icmpv6.bytes}}},
            {"other", {{"packets", snap.l4.other.packets}, {"bytes", snap.l4.other.bytes}}},
            {"none", {{"packets", snap.l4.none.packets}, {"bytes", snap.l4.none.bytes}}}
        }},
        {"top_ports", top_ports_json},
        {"active_alerts", active_alerts_count}
    };

    return dump_json(j);
}

std::string serialize_top_talkers_json(const StatsSnapshot& snap, std::optional<std::size_t> limit) {
    std::size_t total_available = snap.top_talkers.size();
    std::size_t take = limit.has_value() ? std::min(total_available, *limit) : total_available;

    json talkers_json = json::array();
    for (std::size_t i = 0; i < take; ++i) {
        const auto& t = snap.top_talkers[i];
        talkers_json.push_back({
            {"ip", ip_or_null(t.ip)},
            {"packets", t.packets},
            {"bytes", t.bytes}
        });
    }

    json j = {
        {"snapshot_seq", snap.snapshot_seq},
        {"count", talkers_json.size()},
        {"total_available", total_available},
        {"untracked_packets", snap.drops.untracked_talker_packets},
        {"talkers", talkers_json}
    };

    return dump_json(j);
}

std::string serialize_alerts_json(
    const StatsSnapshot& snap,
    AlertFilterState state_filter,
    std::optional<std::size_t> limit) {

    json alerts_json = json::array();
    std::size_t total_matching = 0;

    for (const auto& a : snap.alerts) {
        if (state_filter == AlertFilterState::Active && a.state != AlertState::Active) {
            continue;
        }
        if (state_filter == AlertFilterState::Resolved && a.state != AlertState::Resolved) {
            continue;
        }

        ++total_matching;

        if (!limit.has_value() || alerts_json.size() < *limit) {
            const char* type_str = "unknown";
            switch (a.type) {
                case AlertType::SynFlood:
                    type_str = "syn_flood";
                    break;
                case AlertType::PortScan:
                    type_str = "port_scan";
                    break;
            }

            const char* state_str = (a.state == AlertState::Active) ? "active" : "resolved";

            json ended_at = nullptr;
            if (a.state == AlertState::Resolved) {
                ended_at = format_iso8601_utc(a.ended_at);
            }

            alerts_json.push_back({
                {"id", a.id},
                {"type", type_str},
                {"state", state_str},
                {"src_ip", ip_or_null(a.src_ip)},
                {"dst_ip", ip_or_null(a.dst_ip)},
                {"dst_port", a.dst_port},
                {"started_at", format_iso8601_utc(a.started_at)},
                {"last_seen_at", format_iso8601_utc(a.last_seen_at)},
                {"ended_at", ended_at},
                {"syn_count", a.syn_count},
                {"syn_ack_count", a.syn_ack_count},
                {"unique_ports", a.unique_ports},
                {"peak_rate_pps", safe_double(a.peak_rate_pps)}
            });
        }
    }

    json j = {
        {"snapshot_seq", snap.snapshot_seq},
        {"count", alerts_json.size()},
        {"total_matching", total_matching},
        {"alerts", alerts_json}
    };

    return dump_json(j);
}

std::string serialize_drops_json(const StatsSnapshot& snap) {
    json j = {
        {"snapshot_seq", snap.snapshot_seq},
        {"drops", {
            {"filtered_out", snap.drops.filtered_out},
            {"queue_dropped", snap.drops.queue_dropped},
            {"kernel_dropped", snap.drops.kernel_dropped},
            {"interface_dropped", snap.drops.interface_dropped},
            {"untracked_talker_packets", snap.drops.untracked_talker_packets},
            {"untracked_port_packets", snap.drops.untracked_port_packets},
            {"untracked_syn_targets", snap.drops.untracked_syn_targets},
            {"untracked_scan_sources", snap.drops.untracked_scan_sources}
        }}
    };
    return dump_json(j);
}

std::string serialize_error_json(std::string_view code, std::string_view message) {
    json j = {
        {"error", {
            {"code", code},
            {"message", message}
        }}
    };
    return dump_json(j);
}

}