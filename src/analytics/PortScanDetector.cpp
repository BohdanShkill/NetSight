#include "netsight/analytics/PortScanDetector.hpp"

#include <algorithm>

namespace netsight {

PortScanDetector::PortScanDetector(PortScanConfig cfg)
    : cfg_(cfg), log_(cfg_.max_alerts) {
    if (cfg_.port_threshold == 0) {
        cfg_.port_threshold = 1;
    }
    if (cfg_.port_threshold > kMaxPortsPerSource) {
        cfg_.port_threshold = static_cast<std::uint32_t>(kMaxPortsPerSource);
    }
    if (cfg_.recovery_port_threshold >= cfg_.port_threshold) {
        cfg_.recovery_port_threshold = cfg_.port_threshold - 1;
    }
    if (cfg_.entry_ttl < cfg_.window_duration) {
        cfg_.entry_ttl = cfg_.window_duration;
    }
    if (cfg_.max_tracked_sources == 0) {
        cfg_.max_tracked_sources = 1;
    }
    if (cfg_.max_alerts == 0) {
        cfg_.max_alerts = 1;
    }
}

void PortScanDetector::record(const ParsedPacket& pkt) {
    if (pkt.status != ParseStatus::Ok) {
        return;
    }
    if (pkt.transport != TransportProtocol::TCP) {
        return;
    }
    if (!pkt.src_ip.is_valid() || !pkt.dst_ip.is_valid()) {
        return;
    }
    if (pkt.tcp_flags.ack() || pkt.tcp_flags.rst()) {
        return;
    }

    if (pkt.timestamp > max_seen_ts_) {
        max_seen_ts_ = pkt.timestamp;
    }

    auto it = sources_.find(pkt.src_ip);
    if (it == sources_.end()) {
        if (sources_.size() >= cfg_.max_tracked_sources) {
            evict_expired(max_seen_ts_);
        }
        if (sources_.size() >= cfg_.max_tracked_sources) {
            ++untracked_source_packets_;
            return;
        }
        it = sources_.emplace(pkt.src_ip, SourceState{cfg_.window_duration}).first;
    }

    auto& s = it->second;
    if (pkt.timestamp > s.last_seen) {
        s.last_seen = pkt.timestamp;
    }

    const Timestamp now = s.last_seen;
    expire_ports(s, now);

    if (now.count() - pkt.timestamp.count() < cfg_.window_duration.count()) {
        upsert_port(s, pkt.dst_port, pkt.timestamp);
    }

    s.probe_window.add(pkt.timestamp, 1);
    s.last_dst_ip = pkt.dst_ip;

    evaluate_source(pkt.src_ip, s, now);
}

void PortScanDetector::expire_ports(SourceState& s, Timestamp now) {
    std::size_t i = 0;
    while (i < s.port_count) {
        if (now >= s.ports[i].last_seen && (now - s.ports[i].last_seen) >= cfg_.window_duration) {
            s.ports[i] = s.ports[s.port_count - 1];
            --s.port_count;
        } else {
            ++i;
        }
    }
}

void PortScanDetector::upsert_port(SourceState& s, std::uint16_t port, Timestamp ts) {
    for (std::size_t i = 0; i < s.port_count; ++i) {
        if (s.ports[i].port == port) {
            if (ts > s.ports[i].last_seen) {
                s.ports[i].last_seen = ts;
            }
            return;
        }
    }

    if (s.port_count < kMaxPortsPerSource) {
        s.ports[s.port_count++] = PortSeen{port, ts};
        return;
    }

    std::size_t oldest_idx = 0;
    for (std::size_t i = 1; i < s.port_count; ++i) {
        if (s.ports[i].last_seen < s.ports[oldest_idx].last_seen) {
            oldest_idx = i;
        }
    }
    s.ports[oldest_idx] = PortSeen{port, ts};
}

void PortScanDetector::evaluate_source(const IpAddress& src, SourceState& s, Timestamp ts) {
    const auto unique = static_cast<std::uint32_t>(s.port_count);
    const auto rate = s.probe_window.rate_per_second();

    if (s.active_alert_id == 0) {
        if (unique >= cfg_.port_threshold) {
            Alert alert{};
            alert.type = AlertType::PortScan;
            alert.state = AlertState::Active;
            alert.src_ip = src;
            alert.dst_ip = s.last_dst_ip;
            alert.dst_port = 0;
            alert.started_at = ts;
            alert.last_seen_at = ts;
            alert.ended_at = Timestamp{0};
            alert.syn_count = 0;
            alert.syn_ack_count = 0;
            alert.unique_ports = unique;
            alert.peak_rate_pps = rate;

            s.active_alert_id = log_.open(alert);
        }
    } else {
        Alert* a = log_.find(s.active_alert_id);
        if (a == nullptr) {
            s.active_alert_id = 0;
            return;
        }

        if (unique <= cfg_.recovery_port_threshold) {
            a->state = AlertState::Resolved;
            a->ended_at = std::max(ts, a->last_seen_at);
            s.active_alert_id = 0;
        } else {
            if (ts > a->last_seen_at) {
                a->last_seen_at = ts;
            }
            a->unique_ports = std::max(a->unique_ports, unique);
            if (rate > a->peak_rate_pps) {
                a->peak_rate_pps = rate;
            }
            a->dst_ip = s.last_dst_ip;
        }
    }
}

void PortScanDetector::on_tick(Timestamp now) {
    const Timestamp effective_now = (now > max_seen_ts_) ? now : max_seen_ts_;
    if (effective_now <= Timestamp{0}) {
        return;
    }
    max_seen_ts_ = effective_now;

    for (auto& [src, s] : sources_) {
        expire_ports(s, effective_now);
        s.probe_window.advance(effective_now);
        if (s.active_alert_id != 0) {
            evaluate_source(src, s, effective_now);
        }
    }

    evict_expired(effective_now);
}

void PortScanDetector::evict_expired(Timestamp effective_now) {
    for (auto it = sources_.begin(); it != sources_.end(); ) {
        if (effective_now >= it->second.last_seen &&
            (effective_now - it->second.last_seen) >= cfg_.entry_ttl) {
            if (it->second.active_alert_id != 0) {
                Alert* a = log_.find(it->second.active_alert_id);
                if (a != nullptr && a->state == AlertState::Active) {
                    a->state = AlertState::Resolved;
                    a->ended_at = effective_now;
                }
                it->second.active_alert_id = 0;
            }
            it = sources_.erase(it);
        } else {
            ++it;
        }
    }
}

const std::vector<Alert>& PortScanDetector::alerts() const noexcept {
    return log_.all();
}

std::vector<Alert> PortScanDetector::active_alerts() const {
    return log_.active();
}

std::size_t PortScanDetector::tracked_source_count() const noexcept {
    return sources_.size();
}

std::uint64_t PortScanDetector::untracked_source_packets() const noexcept {
    return untracked_source_packets_;
}

void PortScanDetector::reset() {
    sources_.clear();
    log_.clear();
    untracked_source_packets_ = 0;
    max_seen_ts_ = Timestamp{0};
}

}