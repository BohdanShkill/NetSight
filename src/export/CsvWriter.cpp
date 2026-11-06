#include "netsight/export/CsvWriter.hpp"
#include "netsight/core/Time.hpp"

#include <cstdio>
#include <locale>
#include <ostream>

namespace netsight {

std::string csv_escape(std::string_view field) {
    if (field.find_first_of(",\"\r\n") == std::string_view::npos) {
        return std::string(field);
    }

    std::string escaped;
    escaped.reserve(field.size() + 10);
    escaped.push_back('"');
    for (char c : field) {
        if (c == '"') {
            escaped.push_back('"');
            escaped.push_back('"');
        } else {
            escaped.push_back(c);
        }
    }
    escaped.push_back('"');
    return escaped;
}

void write_summary_csv(std::ostream& out, const StatsSnapshot& snap, const CsvMeta& meta) {
    try {
        out.imbue(std::locale::classic());

        auto put = [&](std::string_view section, std::string_view item, std::string_view metric, std::string_view value) {
            out << csv_escape(section) << ','
                << csv_escape(item) << ','
                << csv_escape(metric) << ','
                << csv_escape(value) << "\r\n";
        };

        auto put_u64 = [&](std::string_view section, std::string_view item, std::string_view metric, std::uint64_t val) {
            put(section, item, metric, std::to_string(val));
        };

        auto put_double = [&](std::string_view section, std::string_view item, std::string_view metric, double val) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.3f", val);
            put(section, item, metric, buf);
        };

        out << "section,item,metric,value\r\n";

        for (const auto& [k, v] : meta) {
            put("meta", "", k, v);
        }

        put_u64("totals", "", "packets", snap.total_packets);
        put_u64("totals", "", "wire_bytes", snap.total_wire_bytes);
        put_u64("totals", "", "captured_bytes", snap.total_captured_bytes);
        put("totals", "", "first_packet", snap.total_packets == 0 ? "" : format_iso8601_utc(snap.first_packet_ts));
        put("totals", "", "last_packet", snap.total_packets == 0 ? "" : format_iso8601_utc(snap.last_packet_ts));
        put_double("totals", "", "duration_seconds", snap.duration_seconds);
        put_double("totals", "", "packets_per_second", snap.packets_per_second);
        put_double("totals", "", "bytes_per_second", snap.bytes_per_second);

        put_u64("parse", "", "ok", snap.status.ok);
        put_u64("parse", "", "truncated", snap.status.truncated);
        put_u64("parse", "", "malformed", snap.status.malformed);
        put_u64("parse", "", "unsupported_link", snap.status.unsupported_link);

        auto put_traffic = [&](std::string_view section, std::string_view item, const TrafficCounter& tc) {
            put_u64(section, item, "packets", tc.packets);
            put_u64(section, item, "bytes", tc.bytes);
        };

        put_traffic("l3", "ipv4", snap.l3.ipv4);
        put_traffic("l3", "ipv6", snap.l3.ipv6);
        put_traffic("l3", "arp", snap.l3.arp);
        put_traffic("l3", "other", snap.l3.other);
        put_u64("l3", "", "vlan_tagged", snap.l3.vlan_tagged_packets);
        put_u64("l3", "", "fragmented", snap.l3.fragmented_packets);

        put_traffic("l4", "tcp", snap.l4.tcp);
        put_traffic("l4", "udp", snap.l4.udp);
        put_traffic("l4", "icmp", snap.l4.icmp);
        put_traffic("l4", "icmpv6", snap.l4.icmpv6);
        put_traffic("l4", "other", snap.l4.other);
        put_traffic("l4", "none", snap.l4.none);

        put_u64("drops", "", "filtered_out", snap.drops.filtered_out);
        put_u64("drops", "", "queue_dropped", snap.drops.queue_dropped);
        put_u64("drops", "", "kernel_dropped", snap.drops.kernel_dropped);
        put_u64("drops", "", "interface_dropped", snap.drops.interface_dropped);
        put_u64("drops", "", "untracked_talker_packets", snap.drops.untracked_talker_packets);
        put_u64("drops", "", "untracked_port_packets", snap.drops.untracked_port_packets);
        put_u64("drops", "", "untracked_syn_targets", snap.drops.untracked_syn_targets);
        put_u64("drops", "", "untracked_scan_sources", snap.drops.untracked_scan_sources);

        for (std::size_t i = 0; i < snap.top_talkers.size(); ++i) {
            const std::string rank = std::to_string(i + 1);
            put("top_talkers", rank, "ip", snap.top_talkers[i].ip.to_string());
            put_u64("top_talkers", rank, "packets", snap.top_talkers[i].packets);
            put_u64("top_talkers", rank, "bytes", snap.top_talkers[i].bytes);
        }

        for (std::size_t i = 0; i < snap.top_ports.size(); ++i) {
            const std::string rank = std::to_string(i + 1);
            put("top_ports", rank, "port", std::to_string(snap.top_ports[i].port));
            put_u64("top_ports", rank, "packets", snap.top_ports[i].packets);
            put_u64("top_ports", rank, "bytes", snap.top_ports[i].bytes);
        }

        for (std::size_t i = 0; i < snap.alerts.size(); ++i) {
            const auto& a = snap.alerts[i];
            const std::string rank = std::to_string(i + 1);
            put_u64("alerts", rank, "id", a.id);
            put("alerts", rank, "type", to_string(a.type));
            put("alerts", rank, "state", to_string(a.state));
            put("alerts", rank, "src_ip", a.src_ip.to_string());
            put("alerts", rank, "dst_ip", a.dst_ip.to_string());
            put("alerts", rank, "dst_port", std::to_string(a.dst_port));
            put("alerts", rank, "started_at", format_iso8601_utc(a.started_at));
            put("alerts", rank, "last_seen_at", format_iso8601_utc(a.last_seen_at));
            put("alerts", rank, "ended_at", a.state == AlertState::Active ? "" : format_iso8601_utc(a.ended_at));
            put_u64("alerts", rank, "syn_count", a.syn_count);
            put_u64("alerts", rank, "syn_ack_count", a.syn_ack_count);
            put_u64("alerts", rank, "unique_ports", a.unique_ports);
            put_double("alerts", rank, "peak_rate_pps", a.peak_rate_pps);
        }

        out.flush();
    } catch (...) {
    }
}

}