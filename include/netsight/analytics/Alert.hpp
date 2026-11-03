#pragma once

#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"

#include <cstdint>
#include <string>

namespace netsight {

enum class AlertType : std::uint8_t {
    SynFlood = 0,
    PortScan = 1
};

enum class AlertState : std::uint8_t {
    Active = 0,
    Resolved = 1
};

inline std::string to_string(AlertType type) {
    switch (type) {
        case AlertType::SynFlood: return "syn_flood";
        case AlertType::PortScan: return "port_scan";
        default:                  return "unknown";
    }
}

inline std::string to_string(AlertState state) {
    switch (state) {
        case AlertState::Active:   return "active";
        case AlertState::Resolved: return "resolved";
        default:                   return "unknown";
    }
}

struct Alert {
    std::uint64_t id{0};
    AlertType type{AlertType::SynFlood};
    AlertState state{AlertState::Active};

    IpAddress src_ip{};
    IpAddress dst_ip{};
    std::uint16_t dst_port{0};

    Timestamp started_at{0};
    Timestamp last_seen_at{0};
    Timestamp ended_at{0};

    std::uint64_t syn_count{0};
    std::uint64_t syn_ack_count{0};
    std::uint32_t unique_ports{0};
    double peak_rate_pps{0.0};

    bool operator==(const Alert& rhs) const noexcept {
        return id == rhs.id &&
               type == rhs.type &&
               state == rhs.state &&
               src_ip == rhs.src_ip &&
               dst_ip == rhs.dst_ip &&
               dst_port == rhs.dst_port &&
               started_at == rhs.started_at &&
               last_seen_at == rhs.last_seen_at &&
               ended_at == rhs.ended_at &&
               syn_count == rhs.syn_count &&
               syn_ack_count == rhs.syn_ack_count &&
               unique_ports == rhs.unique_ports &&
               peak_rate_pps == rhs.peak_rate_pps;
    }

    bool operator!=(const Alert& rhs) const noexcept {
        return !(*this == rhs);
    }
};

}