#include "netsight/export/AgentPoller.hpp"
#include "netsight/export/JsonSerializer.hpp"
#include "netsight/export/RestServer.hpp"
#include "netsight/core/IpAddress.hpp"

#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <memory>
#include <string>

using namespace netsight;

namespace {

IpAddress make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    const std::array<uint8_t, 4> bytes{a, b, c, d};
    return IpAddress::from_ipv4(bytes.data());
}

}

TEST(AgentPollerTest, ParseAgentStatsJsonExtractsMetricsSafely) {
    const std::string json_str = R"({
        "totals": {
            "packets": 1500,
            "wire_bytes": 150000,
            "packets_per_second": 300.0,
            "bytes_per_second": 30000.0
        },
        "l4": {
            "tcp": {"packets": 1000},
            "udp": {"packets": 400},
            "icmp": {"packets": 100}
        },
        "top_ports": [
            {"port": 80, "packets": 500, "bytes": 50000},
            {"port": 443, "packets": 300, "bytes": 30000}
        ],
        "syn_targets": [
            {
                "dst_ip": "10.0.0.50",
                "dst_port": 443,
                "syn_count": 60,
                "syn_ack_count": 2,
                "syn_rate_pps": 60.0
            }
        ],
        "active_alerts": 1
    })";

    AgentMetricsReport report{};
    EXPECT_TRUE(parse_agent_stats_json(json_str, report));

    EXPECT_EQ(report.total_packets, 1500u);
    EXPECT_EQ(report.total_wire_bytes, 150000u);
    EXPECT_DOUBLE_EQ(report.pps, 300.0);
    EXPECT_DOUBLE_EQ(report.bps, 30000.0);
    EXPECT_EQ(report.tcp_packets, 1000u);
    EXPECT_EQ(report.udp_packets, 400u);
    EXPECT_EQ(report.icmp_packets, 100u);

    ASSERT_EQ(report.top_ports.size(), 2u);
    EXPECT_EQ(report.top_ports[0].port, 80u);
    EXPECT_EQ(report.top_ports[1].port, 443u);

    ASSERT_EQ(report.syn_targets.size(), 1u);
    EXPECT_EQ(report.syn_targets[0].dst_ip, make_ip(10, 0, 0, 50));
    EXPECT_EQ(report.syn_targets[0].dst_port, 443u);
    EXPECT_EQ(report.syn_targets[0].syn_count, 60u);
    EXPECT_EQ(report.syn_targets[0].syn_ack_count, 2u);
    EXPECT_DOUBLE_EQ(report.syn_targets[0].syn_rate_pps, 60.0);
    EXPECT_EQ(report.active_alerts_count, 1u);
}

TEST(AgentPollerTest, ParseAgentStatsJsonMalformedReturnsFalse) {
    AgentMetricsReport report{};
    EXPECT_FALSE(parse_agent_stats_json("", report));
    EXPECT_FALSE(parse_agent_stats_json("{invalid_json", report));
    EXPECT_FALSE(parse_agent_stats_json("[]", report));
}

TEST(AgentPollerTest, ParseAgentTopTalkersJsonExtractsTalkersSafely) {
    const std::string json_str = R"({
        "count": 2,
        "talkers": [
            {"ip": "192.168.1.1", "packets": 500, "bytes": 50000},
            {"ip": "10.0.0.1", "packets": 300, "bytes": 30000}
        ]
    })";

    AgentMetricsReport report{};
    EXPECT_TRUE(parse_agent_top_talkers_json(json_str, report));

    ASSERT_EQ(report.top_talkers.size(), 2u);
    EXPECT_EQ(report.top_talkers[0].ip, make_ip(192, 168, 1, 1));
    EXPECT_EQ(report.top_talkers[0].packets, 500u);
    EXPECT_EQ(report.top_talkers[1].ip, make_ip(10, 0, 0, 1));
    EXPECT_EQ(report.top_talkers[1].bytes, 30000u);
}

TEST(AgentPollerTest, ParseAgentTopTalkersMalformedReturnsFalse) {
    AgentMetricsReport report{};
    EXPECT_FALSE(parse_agent_top_talkers_json("not json", report));
}

TEST(AgentPollerTest, PollAgentInvalidEndpointReturnsError) {
    AgentPoller poller{};
    const auto report = poller.poll_agent("invalid_host:not_a_port");

    EXPECT_FALSE(report.online);
    EXPECT_EQ(report.error_message, "Invalid endpoint format");
}

TEST(AgentPollerTest, PollAgentUnreachableServerReturnsConnectionFailed) {
    AgentPollerConfig cfg{};
    cfg.timeout_ms = 100;
    AgentPoller poller{cfg};

    const auto report = poller.poll_agent("127.0.0.1:49999");

    EXPECT_FALSE(report.online);
    EXPECT_EQ(report.error_message, "Connection failed");
}

TEST(AgentPollerTest, PollAgentIntegrationWithLiveRestServer) {
    auto snap = std::make_shared<StatsSnapshot>();
    snap->total_packets = 500;
    snap->total_wire_bytes = 50000;
    snap->packets_per_second = 50.0;
    snap->bytes_per_second = 5000.0;
    snap->l4.tcp.packets = 400;
    snap->l4.udp.packets = 100;
    snap->top_ports = {PortEntry{80, 200, 20000}};
    snap->top_talkers = {TalkerEntry{make_ip(10, 0, 0, 1), 300, 30000}};
    snap->syn_targets = {SynTargetEntry{make_ip(10, 0, 0, 99), 443, 80, 5, 80.0}};

    RestConfig server_cfg{};
    server_cfg.host = "127.0.0.1";
    server_cfg.port = 0;

    RestServer server(server_cfg, [snap]() { return snap; });
    std::string err;
    ASSERT_TRUE(server.start(err));
    const auto port = server.bound_port();
    ASSERT_GT(port, 0);

    AgentPollerConfig poller_cfg{};
    poller_cfg.timeout_ms = 2000;
    AgentPoller poller{poller_cfg};

    const auto report = poller.poll_agent("127.0.0.1:" + std::to_string(port));

    EXPECT_TRUE(report.online);
    EXPECT_TRUE(report.error_message.empty());
    EXPECT_EQ(report.total_packets, 500u);
    EXPECT_DOUBLE_EQ(report.pps, 50.0);
    EXPECT_EQ(report.tcp_packets, 400u);
    EXPECT_EQ(report.udp_packets, 100u);

    ASSERT_EQ(report.top_ports.size(), 1u);
    EXPECT_EQ(report.top_ports[0].port, 80u);

    ASSERT_EQ(report.top_talkers.size(), 1u);
    EXPECT_EQ(report.top_talkers[0].ip, make_ip(10, 0, 0, 1));

    ASSERT_EQ(report.syn_targets.size(), 1u);
    EXPECT_EQ(report.syn_targets[0].dst_ip, make_ip(10, 0, 0, 99));
    EXPECT_EQ(report.syn_targets[0].dst_port, 443u);
    EXPECT_EQ(report.syn_targets[0].syn_count, 80u);

    server.stop();
}

TEST(AgentPollerTest, PollAgentWithBearerAuthRejectsUnauthorizedAndAcceptsAuthorized) {
    auto snap = std::make_shared<StatsSnapshot>();
    snap->total_packets = 100;

    RestConfig server_cfg{};
    server_cfg.host = "127.0.0.1";
    server_cfg.port = 0;
    server_cfg.bearer_token = "secret123";

    RestServer server(server_cfg, [snap]() { return snap; });
    std::string err;
    ASSERT_TRUE(server.start(err));
    const auto port = server.bound_port();

    AgentPollerConfig unauth_cfg{};
    unauth_cfg.timeout_ms = 2000;
    AgentPoller unauth_poller{unauth_cfg};
    const auto bad_report = unauth_poller.poll_agent("127.0.0.1:" + std::to_string(port));
    EXPECT_FALSE(bad_report.online);
    EXPECT_EQ(bad_report.error_message, "HTTP status 401");

    AgentPollerConfig auth_cfg{};
    auth_cfg.timeout_ms = 2000;
    auth_cfg.api_token = "secret123";
    AgentPoller auth_poller{auth_cfg};
    const auto good_report = auth_poller.poll_agent("127.0.0.1:" + std::to_string(port));
    EXPECT_TRUE(good_report.online);
    EXPECT_EQ(good_report.total_packets, 100u);

    server.stop();
}

TEST(AgentPollerTest, PollAllReturnsReportsForMultipleAgents) {
    auto snap = std::make_shared<StatsSnapshot>();
    snap->total_packets = 42;

    RestConfig server_cfg{};
    server_cfg.host = "127.0.0.1";
    server_cfg.port = 0;

    RestServer server(server_cfg, [snap]() { return snap; });
    std::string err;
    ASSERT_TRUE(server.start(err));
    const auto port = server.bound_port();

    AgentPollerConfig poller_cfg{};
    poller_cfg.timeout_ms = 500;
    AgentPoller poller{poller_cfg};

    const std::vector<std::string> endpoints = {
        "127.0.0.1:" + std::to_string(port),
        "127.0.0.1:49998"
    };

    const auto reports = poller.poll_all(endpoints);

    ASSERT_EQ(reports.size(), 2u);
    EXPECT_TRUE(reports[0].online);
    EXPECT_EQ(reports[0].total_packets, 42u);

    EXPECT_FALSE(reports[1].online);
    EXPECT_EQ(reports[1].error_message, "Connection failed");

    server.stop();
}