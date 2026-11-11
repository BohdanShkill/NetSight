#include "netsight/export/AgentPoller.hpp"

#include "netsight/export/JsonSerializer.hpp"

#include <charconv>
#include <chrono>
#include <httplib.h>

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
    : cfg_(std::move(cfg)) {}

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

    auto res_stats = cli.Get("/api/v1/stats");
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

    if (!parse_agent_stats_json(res_stats->body, report)) {
        report.online = false;
        report.error_message = "Malformed stats JSON";
        return report;
    }

    auto res_talkers = cli.Get("/api/v1/top-talkers");
    if (res_talkers && res_talkers->status == 200) {
        static_cast<void>(parse_agent_top_talkers_json(res_talkers->body, report));
    }

    report.online = true;
    report.error_message.clear();
    return report;
}

std::vector<AgentMetricsReport> AgentPoller::poll_all(const std::vector<std::string>& agent_addresses) const {
    std::vector<AgentMetricsReport> reports;
    reports.reserve(agent_addresses.size());
    for (const auto& addr : agent_addresses) {
        reports.push_back(poll_agent(addr));
    }
    return reports;
}

}