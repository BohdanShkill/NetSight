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

    json syn_targets_json = json::array();
    for (const auto& t : snap.syn_targets) {
        syn_targets_json.push_back({
            {"dst_ip", ip_or_null(t.dst_ip)},
            {"dst_port", t.dst_port},
            {"syn_count", t.syn_count},
            {"syn_ack_count", t.syn_ack_count},
            {"syn_rate_pps", safe_double(t.syn_rate_pps)}
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
        {"syn_targets", syn_targets_json},
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

bool parse_agent_stats_json(std::string_view json_str, AgentMetricsReport& out) noexcept {
    try {
        auto j = json::parse(json_str, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            return false;
        }

        if (j.contains("totals") && j["totals"].is_object()) {
            const auto& totals = j["totals"];
            out.total_packets = totals.value("packets", std::uint64_t{0});
            out.total_wire_bytes = totals.value("wire_bytes", std::uint64_t{0});
            out.pps = totals.value("packets_per_second", 0.0);
            out.bps = totals.value("bytes_per_second", 0.0);

            const double dur = totals.value("duration_seconds", 0.0);
            out.capture_duration_seconds = (std::isfinite(dur) && dur >= 0.0) ? dur : 0.0;
        }

        if (j.contains("l4") && j["l4"].is_object()) {
            const auto& l4 = j["l4"];
            if (l4.contains("tcp") && l4["tcp"].is_object()) {
                out.tcp_packets = l4["tcp"].value("packets", std::uint64_t{0});
            }
            if (l4.contains("udp") && l4["udp"].is_object()) {
                out.udp_packets = l4["udp"].value("packets", std::uint64_t{0});
            }
            if (l4.contains("icmp") && l4["icmp"].is_object()) {
                out.icmp_packets = l4["icmp"].value("packets", std::uint64_t{0});
            }
            if (l4.contains("icmpv6") && l4["icmpv6"].is_object()) {
                out.icmp_packets += l4["icmpv6"].value("packets", std::uint64_t{0});
            }
            if (l4.contains("other") && l4["other"].is_object()) {
                out.other_packets = l4["other"].value("packets", std::uint64_t{0});
            }
        }

        if (j.contains("top_ports") && j["top_ports"].is_array()) {
            out.top_ports.clear();
            std::size_t count = 0;
            for (const auto& item : j["top_ports"]) {
                if (count >= 256) {
                    break;
                }
                if (item.is_object()) {
                    PortEntry p{};
                    p.port = item.value("port", std::uint16_t{0});
                    p.packets = item.value("packets", std::uint64_t{0});
                    p.bytes = item.value("bytes", std::uint64_t{0});
                    out.top_ports.push_back(p);
                    ++count;
                }
            }
        }

        if (j.contains("syn_targets") && j["syn_targets"].is_array()) {
            out.syn_targets.clear();
            std::size_t count = 0;
            for (const auto& item : j["syn_targets"]) {
                if (count >= 256) {
                    break;
                }
                if (item.is_object()) {
                    SynTargetEntry t{};
                    const auto ip_str = item.value("dst_ip", std::string{});
                    if (auto parsed_ip = parse_ip_address(ip_str)) {
                        t.dst_ip = *parsed_ip;
                    }
                    t.dst_port = item.value("dst_port", std::uint16_t{0});
                    t.syn_count = item.value("syn_count", std::uint64_t{0});
                    t.syn_ack_count = item.value("syn_ack_count", std::uint64_t{0});
                    t.syn_rate_pps = item.value("syn_rate_pps", 0.0);
                    out.syn_targets.push_back(t);
                    ++count;
                }
            }
        }

        if (j.contains("active_alerts") && j["active_alerts"].is_number()) {
            out.active_alerts_count = j.value("active_alerts", std::size_t{0});
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool parse_agent_top_talkers_json(std::string_view json_str, AgentMetricsReport& out) noexcept {
    try {
        auto j = json::parse(json_str, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            return false;
        }

        const auto* arr_ptr = j.contains("talkers") && j["talkers"].is_array() ? &j["talkers"] : nullptr;
        if (!arr_ptr && j.contains("top_talkers") && j["top_talkers"].is_array()) {
            arr_ptr = &j["top_talkers"];
        }

        if (arr_ptr) {
            out.top_talkers.clear();
            std::size_t count = 0;
            for (const auto& item : *arr_ptr) {
                if (count >= 256) {
                    break;
                }
                if (item.is_object()) {
                    TalkerEntry t{};
                    const auto ip_str = item.value("ip", std::string{});
                    if (auto parsed_ip = parse_ip_address(ip_str)) {
                        t.ip = *parsed_ip;
                    }
                    t.packets = item.value("packets", std::uint64_t{0});
                    t.bytes = item.value("bytes", std::uint64_t{0});
                    out.top_talkers.push_back(t);
                    ++count;
                }
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

}