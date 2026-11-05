#pragma once

#include "netsight/analytics/PortScanDetector.hpp"
#include "netsight/analytics/StatsAggregator.hpp"
#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/analytics/SynFloodDetector.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/parser/ParsedPacket.hpp"

#include <memory>
#include <vector>

namespace netsight {

struct AnalyzerConfig {
    StatsConfig stats{};
    SynFloodConfig syn_flood{};
    PortScanConfig port_scan{};
    Timestamp housekeeping_interval{1'000'000};
};

class TrafficAnalyzer {
public:
    explicit TrafficAnalyzer(AnalyzerConfig cfg = {});
    ~TrafficAnalyzer() = default;

    TrafficAnalyzer(const TrafficAnalyzer&) = delete;
    TrafficAnalyzer& operator=(const TrafficAnalyzer&) = delete;
    TrafficAnalyzer(TrafficAnalyzer&&) = delete;
    TrafficAnalyzer& operator=(TrafficAnalyzer&&) = delete;

    void record(const ParsedPacket& pkt);

    std::shared_ptr<const StatsSnapshot> on_tick(Timestamp now = Timestamp{0},
                                                 const DropCounters& external_drops = {});

    [[nodiscard]] std::shared_ptr<const StatsSnapshot> latest_snapshot() const noexcept;

    void reset();

private:
    AnalyzerConfig cfg_;
    StatsAggregator stats_;
    SynFloodDetector syn_;
    PortScanDetector scan_;
    Timestamp last_housekeeping_{0};
};

}