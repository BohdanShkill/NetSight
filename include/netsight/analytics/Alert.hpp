#pragma once

#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

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

class AlertLog {
public:
    explicit AlertLog(std::size_t max_alerts)
        : max_alerts_(max_alerts == 0 ? 1 : max_alerts) {}

    std::uint64_t open(Alert alert) {
        alert.id = ++next_id_;

        if (alerts_.size() >= max_alerts_) {
            auto it = std::find_if(alerts_.begin(), alerts_.end(), [](const Alert& a) noexcept {
                return a.state == AlertState::Resolved;
            });

            if (it != alerts_.end()) {
                alerts_.erase(it);
            } else {
                alerts_.erase(alerts_.begin());
            }
        }

        alerts_.push_back(std::move(alert));
        return alerts_.back().id;
    }

    Alert* find(std::uint64_t id) noexcept {
        for (auto it = alerts_.rbegin(); it != alerts_.rend(); ++it) {
            if (it->id == id) {
                return &(*it);
            }
        }
        return nullptr;
    }

    const Alert* find(std::uint64_t id) const noexcept {
        for (auto it = alerts_.rbegin(); it != alerts_.rend(); ++it) {
            if (it->id == id) {
                return &(*it);
            }
        }
        return nullptr;
    }

    const std::vector<Alert>& all() const noexcept {
        return alerts_;
    }

    std::vector<Alert> active() const {
        std::vector<Alert> res;
        for (const auto& a : alerts_) {
            if (a.state == AlertState::Active) {
                res.push_back(a);
            }
        }
        return res;
    }

    void clear() noexcept {
        alerts_.clear();
        next_id_ = 0;
    }

    std::size_t size() const noexcept {
        return alerts_.size();
    }

    std::size_t capacity() const noexcept {
        return max_alerts_;
    }

private:
    std::size_t max_alerts_{1};
    std::vector<Alert> alerts_{};
    std::uint64_t next_id_{0};
};

}