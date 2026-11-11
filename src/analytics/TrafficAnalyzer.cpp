#include "netsight/analytics/TrafficAnalyzer.hpp"

#include <algorithm>
#include <utility>

namespace netsight {

TrafficAnalyzer::TrafficAnalyzer(AnalyzerConfig cfg)
    : cfg_(cfg),
      stats_(cfg_.stats),
      syn_(cfg_.syn_flood),
      scan_(cfg_.port_scan) {
    if (cfg_.housekeeping_interval <= Timestamp{0}) {
        cfg_.housekeeping_interval = Timestamp{1'000'000};
    }
}

void TrafficAnalyzer::record(const ParsedPacket& pkt) {
    stats_.record(pkt);
    syn_.record(pkt);
    scan_.record(pkt);

    if (pkt.timestamp <= Timestamp{0}) {
        return;
    }

    if (last_housekeeping_ == Timestamp{0}) {
        last_housekeeping_ = pkt.timestamp;
        return;
    }

    if (pkt.timestamp >= last_housekeeping_ &&
        (pkt.timestamp - last_housekeeping_) >= cfg_.housekeeping_interval) {
        syn_.on_tick(pkt.timestamp);
        scan_.on_tick(pkt.timestamp);
        last_housekeeping_ = pkt.timestamp;
    }
}

std::shared_ptr<const StatsSnapshot> TrafficAnalyzer::on_tick(Timestamp now,
                                                             const DropCounters& external_drops) {
    if (now > Timestamp{0}) {
        syn_.on_tick(now);
        scan_.on_tick(now);
    }

    DropCounters drops = external_drops;
    drops.untracked_syn_targets = syn_.untracked_target_packets();
    drops.untracked_scan_sources = scan_.untracked_source_packets();

    std::vector<Alert> alerts;
    const auto& syn_alerts = syn_.alerts();
    const auto& scan_alerts = scan_.alerts();
    alerts.reserve(syn_alerts.size() + scan_alerts.size());
    alerts.insert(alerts.end(), syn_alerts.begin(), syn_alerts.end());
    alerts.insert(alerts.end(), scan_alerts.begin(), scan_alerts.end());

    std::sort(alerts.begin(), alerts.end(), [](const Alert& a, const Alert& b) noexcept {
        if (a.started_at != b.started_at) {
            return a.started_at < b.started_at;
        }
        if (a.type != b.type) {
            return static_cast<std::uint8_t>(a.type) < static_cast<std::uint8_t>(b.type);
        }
        return a.id < b.id;
    });

    auto syn_targets = syn_.top_targets(16);

    return stats_.publish(drops, std::move(alerts), std::move(syn_targets));
}

std::shared_ptr<const StatsSnapshot> TrafficAnalyzer::latest_snapshot() const noexcept {
    return stats_.latest_snapshot();
}

void TrafficAnalyzer::reset() {
    stats_.reset();
    syn_.reset();
    scan_.reset();
    last_housekeeping_ = Timestamp{0};
}

}