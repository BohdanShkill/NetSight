#include "netsight/export/AgentPoller.hpp"

#include "netsight/export/JsonSerializer.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <future>
#include <httplib.h>
#include <system_error>
#include <utility>
#include <vector>

namespace netsight {

namespace {

bool parse_endpoint(std::string_view endpoint, std::string& out_host, int& out_port) {
    if (endpoint.empty()) {
        return false;
    }
    if (endpoint.rfind("http://", 0) == 0) {
        endpoint.remove_prefix(7);
    } else if (endpoint.rfind("https://", 0) == 0) {
        endpoint.remove_prefix(8);
    }
    const auto colon_pos = endpoint.rfind(':');
    if (colon_pos == std::string_view::npos) {
        out_host = std::string(endpoint);
        out_port = 80;
        return !out_host.empty();
    }
    out_host = std::string(endpoint.substr(0, colon_pos));
    std::string_view port_str = endpoint.substr(colon_pos + 1);
    int p = 0;
    auto [ptr, ec] = std::from_chars(port_str.data(), port_str.data() + port_str.size(), p);
    if (ec != std::errc{} || ptr != port_str.data() + port_str.size() || p <= 0 || p > 65535) {
        return false;
    }
    out_port = p;
    return !out_host.empty();
}

}

AgentPoller::AgentPoller(AgentPollerConfig cfg)
    : cfg_(std::move(cfg)) {
    if (cfg_.max_parallel == 0) {
        cfg_.max_parallel = 1;
    }
}

AgentMetricsReport AgentPoller::poll_agent(std::string_view host_port) const {
    AgentMetricsReport report{};
    report.agent_id = std::string(host_port);

    std::string host;
    int port = 0;
    if (!parse_endpoint(host_port, host, port)) {
        report.online = false;
        report.error_message = "Invalid endpoint format";
        return report;
    }

    httplib::Client cli(host, port);
    cli.set_connection_timeout(std::chrono::milliseconds(cfg_.timeout_ms));
    cli.set_read_timeout(std::chrono::milliseconds(cfg_.timeout_ms));

    if (!cfg_.api_token.empty()) {
        cli.set_bearer_token_auth(cfg_.api_token);
    }

    std::string stats_body;
    bool stats_too_large = false;
    auto stats_receiver = [&](const char* data, size_t data_length) {
        if (stats_body.size() + data_length > cfg_.max_body_bytes) {
            stats_too_large = true;
            return false;
        }
        stats_body.append(data, data_length);
        return true;
    };

    auto res_stats = cli.Get("/api/v1/stats", stats_receiver);
    if (stats_too_large) {
        report.online = false;
        report.error_message = "Response too large";
        return report;
    }

    if (!res_stats) {
        report.online = false;
        report.error_message = "Connection failed";
        return report;
    }

    if (res_stats->status != 200) {
        report.online = false;
        report.error_message = "HTTP status " + std::to_string(res_stats->status);
        return report;
    }

    if (!parse_agent_stats_json(stats_body, report)) {
        report.online = false;
        report.error_message = "Malformed stats JSON";
        return report;
    }

    std::string talkers_body;
    bool talkers_too_large = false;
    auto talkers_receiver = [&](const char* data, size_t data_length) {
        if (talkers_body.size() + data_length > cfg_.max_body_bytes) {
            talkers_too_large = true;
            return false;
        }
        talkers_body.append(data, data_length);
        return true;
    };

    auto res_talkers = cli.Get("/api/v1/top-talkers", talkers_receiver);
    if (talkers_too_large) {
        report.online = false;
        report.error_message = "Response too large";
        return report;
    }

    if (res_talkers && res_talkers->status == 200) {
        static_cast<void>(parse_agent_top_talkers_json(talkers_body, report));
    }

    report.online = true;
    report.error_message.clear();
    return report;
}

std::vector<AgentMetricsReport> AgentPoller::poll_all(const std::vector<std::string>& agent_addresses) const {
    const std::size_t n = agent_addresses.size();
    std::vector<AgentMetricsReport> results(n);
    for (std::size_t i = 0; i < n; ++i) {
        results[i].agent_id = agent_addresses[i];
    }

    const std::size_t chunk_size = cfg_.max_parallel == 0 ? 1 : cfg_.max_parallel;

    for (std::size_t wave_start = 0; wave_start < n; wave_start += chunk_size) {
        const std::size_t wave_end = std::min(wave_start + chunk_size, n);
        std::vector<std::pair<std::size_t, std::future<AgentMetricsReport>>> futures;
        futures.reserve(wave_end - wave_start);

        for (std::size_t i = wave_start; i < wave_end; ++i) {
            try {
                futures.emplace_back(i, std::async(std::launch::async, [this, &agent_addresses, i]() {
                    return poll_agent(agent_addresses[i]);
                }));
            } catch (const std::system_error&) {
                results[i] = poll_agent(agent_addresses[i]);
            }
        }

        for (auto& [idx, fut] : futures) {
            try {
                results[idx] = fut.get();
            } catch (...) {
                results[idx].online = false;
                results[idx].error_message = "Internal poll error";
            }
        }
    }

    return results;
}

}