#include "netsight/analytics/SynFloodDetector.hpp"

#include <algorithm>

namespace netsight {

SynFloodDetector::SynFloodDetector(SynFloodConfig cfg)
    : cfg_(cfg), log_(cfg_.max_alerts) {
    if (cfg_.syn_threshold == 0) {
        cfg_.syn_threshold = 1;
    }
    if (cfg_.recovery_syn_threshold >= cfg_.syn_threshold) {
        cfg_.recovery_syn_threshold = cfg_.syn_threshold - 1;
    }
    if (cfg_.max_tracked_targets == 0) {
        cfg_.max_tracked_targets = 1;
    }
    if (cfg_.max_alerts == 0) {
        cfg_.max_alerts = 1;
    }
}

void SynFloodDetector::record(const ParsedPacket& pkt) {
    if (pkt.status != ParseStatus::Ok) {
        return;
    }
    if (pkt.transport != TransportProtocol::TCP) {
        return;
    }
    if (!pkt.src_ip.is_valid() || !pkt.dst_ip.is_valid()) {
        return;
    }
    if (pkt.tcp_flags.rst() || !pkt.tcp_flags.syn()) {
        return;
    }

    if (pkt.timestamp > max_seen_ts_) {
        max_seen_ts_ = pkt.timestamp;
    }

    if (!pkt.tcp_flags.ack()) {
        EndpointKey key{pkt.dst_ip, pkt.dst_port};
        auto it = targets_.find(key);
        if (it == targets_.end()) {
            if (targets_.size() >= cfg_.max_tracked_targets) {
                evict_expired(max_seen_ts_);
            }
            if (targets_.size() >= cfg_.max_tracked_targets) {
                ++untracked_target_packets_;
                return;
            }
            it = targets_.emplace(key, TargetState{cfg_.window_duration}).first;
        }

        auto& target = it->second;
        target.syn_window.add(pkt.timestamp, 1);
        target.syn_ack_window.advance(pkt.timestamp);
        if (pkt.timestamp > target.last_seen) {
            target.last_seen = pkt.timestamp;
        }

        evaluate_target(key, target, pkt.timestamp);
        return;
    }

    EndpointKey key{pkt.src_ip, pkt.src_port};
    auto it = targets_.find(key);
    if (it == targets_.end()) {
        return;
    }

    auto& target = it->second;
    target.syn_window.advance(pkt.timestamp);
    target.syn_ack_window.add(pkt.timestamp, 1);
    if (pkt.timestamp > target.last_seen) {
        target.last_seen = pkt.timestamp;
    }

    evaluate_target(key, target, pkt.timestamp);
}

void SynFloodDetector::evaluate_target(const EndpointKey& key, TargetState& target, Timestamp ts) {
    const auto syns = target.syn_window.total();
    const auto syn_acks = target.syn_ack_window.total();
    const auto rate_pps = target.syn_window.rate_per_second();
    const double ratio = (syns > 0) ? (static_cast<double>(syn_acks) / static_cast<double>(syns)) : 0.0;

    if (target.active_alert_id == 0) {
        if (syns >= cfg_.syn_threshold && ratio <= cfg_.max_syn_ack_ratio) {
            Alert alert{};
            alert.type = AlertType::SynFlood;
            alert.state = AlertState::Active;
            alert.src_ip = IpAddress{};
            alert.dst_ip = key.ip;
            alert.dst_port = key.port;
            alert.started_at = ts;
            alert.last_seen_at = ts;
            alert.ended_at = Timestamp{0};
            alert.syn_count = syns;
            alert.syn_ack_count = syn_acks;
            alert.unique_ports = 0;
            alert.peak_rate_pps = rate_pps;

            target.active_alert_id = log_.open(alert);
        }
    } else {
        Alert* alert_ptr = log_.find(target.active_alert_id);
        if (alert_ptr == nullptr) {
            target.active_alert_id = 0;
            return;
        }

        if (syns <= cfg_.recovery_syn_threshold) {
            alert_ptr->state = AlertState::Resolved;
            alert_ptr->ended_at = std::max(ts, alert_ptr->last_seen_at);
            alert_ptr->syn_count = syns;
            alert_ptr->syn_ack_count = syn_acks;
            target.active_alert_id = 0;
        } else {
            if (ts > alert_ptr->last_seen_at) {
                alert_ptr->last_seen_at = ts;
            }
            alert_ptr->syn_count = syns;
            alert_ptr->syn_ack_count = syn_acks;
            if (rate_pps > alert_ptr->peak_rate_pps) {
                alert_ptr->peak_rate_pps = rate_pps;
            }
        }
    }
}

void SynFloodDetector::on_tick(Timestamp now) {
    const Timestamp effective_now = (now > max_seen_ts_) ? now : max_seen_ts_;
    if (effective_now <= Timestamp{0}) {
        return;
    }
    max_seen_ts_ = effective_now;

    for (auto& [key, target] : targets_) {
        target.syn_window.advance(effective_now);
        target.syn_ack_window.advance(effective_now);
        if (target.active_alert_id != 0) {
            evaluate_target(key, target, effective_now);
        }
    }

    evict_expired(effective_now);
}

void SynFloodDetector::evict_expired(Timestamp effective_now) {
    for (auto it = targets_.begin(); it != targets_.end(); ) {
        if (effective_now >= it->second.last_seen &&
            (effective_now - it->second.last_seen) >= cfg_.entry_ttl) {
            if (it->second.active_alert_id != 0) {
                Alert* alert_ptr = log_.find(it->second.active_alert_id);
                if (alert_ptr != nullptr && alert_ptr->state == AlertState::Active) {
                    alert_ptr->state = AlertState::Resolved;
                    alert_ptr->ended_at = effective_now;
                }
                it->second.active_alert_id = 0;
            }
            it = targets_.erase(it);
        } else {
            ++it;
        }
    }
}

const std::vector<Alert>& SynFloodDetector::alerts() const noexcept {
    return log_.all();
}

std::vector<Alert> SynFloodDetector::active_alerts() const {
    return log_.active();
}

std::size_t SynFloodDetector::tracked_target_count() const noexcept {
    return targets_.size();
}

std::uint64_t SynFloodDetector::untracked_target_packets() const noexcept {
    return untracked_target_packets_;
}

void SynFloodDetector::reset() {
    targets_.clear();
    log_.clear();
    untracked_target_packets_ = 0;
    max_seen_ts_ = Timestamp{0};
}

}