#pragma once

#include "netsight/analytics/StatsSnapshot.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace netsight {

inline constexpr std::size_t kDefaultMaxApiLimit = 1000;

enum class AlertFilterState : std::uint8_t {
    All = 0,
    Active = 1,
    Resolved = 2
};

[[nodiscard]] std::optional<std::size_t> parse_limit_param(
    std::string_view raw,
    std::size_t max_limit = kDefaultMaxApiLimit) noexcept;

[[nodiscard]] std::optional<AlertFilterState> parse_alert_state_param(
    std::string_view raw) noexcept;

[[nodiscard]] std::string serialize_health_json(
    std::string_view version,
    std::uint64_t snapshot_seq);

[[nodiscard]] std::string serialize_stats_json(const StatsSnapshot& snap);

[[nodiscard]] std::string serialize_top_talkers_json(
    const StatsSnapshot& snap,
    std::optional<std::size_t> limit = std::nullopt);

[[nodiscard]] std::string serialize_alerts_json(
    const StatsSnapshot& snap,
    AlertFilterState state_filter = AlertFilterState::All,
    std::optional<std::size_t> limit = std::nullopt);

[[nodiscard]] std::string serialize_drops_json(const StatsSnapshot& snap);

[[nodiscard]] std::string serialize_error_json(
    std::string_view code,
    std::string_view message);

}