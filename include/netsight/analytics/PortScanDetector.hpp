#pragma once

#include "netsight/analytics/Alert.hpp"
#include "netsight/analytics/SlidingWindow.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/parser/ParsedPacket.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace netsight {

struct PortScanConfig {
    Timestamp window_duration{5'000'000};
    std::uint32_t port_threshold{20};
    std::uint32_t recovery_port_threshold{5};
    Timestamp entry_ttl{10'000'000};
    std::size_t max_tracked_sources{4096};
    std::size_t max_alerts{256};
};

class PortScanDetector {
public:
    static constexpr std::size_t kMaxPortsPerSource = 64;

    explicit PortScanDetector(PortScanConfig cfg = {});
    ~PortScanDetector() = default;

    PortScanDetector(const PortScanDetector&) = delete;
    PortScanDetector& operator=(const PortScanDetector&) = delete;
    PortScanDetector(PortScanDetector&&) = delete;
    PortScanDetector& operator=(PortScanDetector&&) = delete;

    void record(const ParsedPacket& pkt);

    void on_tick(Timestamp now = Timestamp{0});

    [[nodiscard]] const std::vector<Alert>& alerts() const noexcept;
    [[nodiscard]] std::vector<Alert> active_alerts() const;
    [[nodiscard]] std::size_t tracked_source_count() const noexcept;
    [[nodiscard]] std::uint64_t untracked_source_packets() const noexcept;
    void reset();

private:
    struct PortSeen {
        std::uint16_t port{0};
        Timestamp last_seen{0};
    };

    struct SourceState {
        std::array<PortSeen, kMaxPortsPerSource> ports{};
        std::size_t port_count{0};
        SlidingWindow<10> probe_window;
        Timestamp last_seen{0};
        IpAddress last_dst_ip{};
        std::uint64_t active_alert_id{0};

        explicit SourceState(Timestamp window_duration)
            : probe_window(window_duration) {}
    };

    void expire_ports(SourceState& s, Timestamp now);
    void upsert_port(SourceState& s, std::uint16_t port, Timestamp ts);
    void evaluate_source(const IpAddress& src, SourceState& s, Timestamp ts);
    void evict_expired(Timestamp effective_now);

    PortScanConfig cfg_;
    std::unordered_map<IpAddress, SourceState> sources_;
    AlertLog log_;
    std::uint64_t untracked_source_packets_{0};
    Timestamp max_seen_ts_{0};
};

}