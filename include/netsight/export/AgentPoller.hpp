#pragma once

#include "netsight/analytics/DistributedAggregator.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace netsight {

struct AgentPollerConfig {
    std::uint32_t timeout_ms{1000};
    std::string api_token{};
};

class AgentPoller {
public:
    explicit AgentPoller(AgentPollerConfig cfg = {});
    ~AgentPoller() = default;

    [[nodiscard]] AgentMetricsReport poll_agent(std::string_view host_port) const;
    [[nodiscard]] std::vector<AgentMetricsReport> poll_all(const std::vector<std::string>& agent_addresses) const;

    [[nodiscard]] const AgentPollerConfig& config() const noexcept { return cfg_; }
    void set_config(AgentPollerConfig cfg) noexcept { cfg_ = std::move(cfg); }

private:
    AgentPollerConfig cfg_;
};

}