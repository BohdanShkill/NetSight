#include "netsight/analytics/DistributedAggregator.hpp"
#include "netsight/core/IpAddress.hpp"

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <vector>

using namespace netsight;

namespace {

IpAddress make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    const std::array<uint8_t, 4> bytes{a, b, c, d};
    return IpAddress::from_ipv4(bytes.data());
}

}

TEST(DistributedAggregatorTest, EmptyReportsProducesZeroedSnapshot) {
    DistributedAggregator agg{};
    const auto snap = agg.aggregate({});

    EXPECT_EQ(snap.total_agents, 0u);
    EXPECT_EQ(snap.online_agents, 0u);
    EXPECT_EQ(snap.interval_agents, 0u);
    EXPECT_EQ(snap.total_packets, 0u);
    EXPECT_EQ(snap.total_wire_bytes, 0u);
    EXPECT_EQ(snap.interval_packets, 0u);
    EXPECT_DOUBLE_EQ(snap.global_pps, 0.0);
    EXPECT_DOUBLE_EQ(snap.global_bps, 0.0);
    EXPECT_TRUE(snap.merged_top_talkers.empty());
    EXPECT_TRUE(snap.merged_top_ports.empty());
    EXPECT_TRUE(snap.merged_syn_targets.empty());
    EXPECT_TRUE(snap.alerts.empty());
}

TEST(DistributedAggregatorTest, AllOfflineAgentsProducesZeroedMetricsWithCorrectTotalAgents) {
    DistributedAggregator agg{};
    AgentMetricsReport r1{};
    r1.agent_id = "agent1";
    r1.online = false;
    r1.total_packets = 1000;

    AgentMetricsReport r2{};
    r2.agent_id = "agent2";
    r2.online = false;
    r2.total_packets = 2000;

    const auto snap = agg.aggregate({r1, r2});

    EXPECT_EQ(snap.total_agents, 2u);
    EXPECT_EQ(snap.online_agents, 0u);
    EXPECT_EQ(snap.interval_agents, 0u);
    EXPECT_EQ(snap.total_packets, 0u);
    EXPECT_TRUE(snap.alerts.empty());
}

TEST(DistributedAggregatorTest, SubThresholdDistributedSynFloodTriggersAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 3;
    cfg.global_syn_pps_threshold = 100.0;
    cfg.max_syn_ack_ratio = 0.25;
    DistributedAggregator agg{cfg};

    const auto victim_ip = make_ip(10, 0, 0, 50);
    const uint16_t victim_port = 443;

    SynTargetEntry t1{victim_ip, victim_port, 45, 2, 45.0};
    SynTargetEntry t2{victim_ip, victim_port, 45, 2, 45.0};
    SynTargetEntry t3{victim_ip, victim_port, 45, 2, 45.0};

    AgentMetricsReport a1{};
    a1.agent_id = "agent1";
    a1.online = true;
    a1.syn_targets = {t1};

    AgentMetricsReport a2{};
    a2.agent_id = "agent2";
    a2.online = true;
    a2.syn_targets = {t2};

    AgentMetricsReport a3{};
    a3.agent_id = "agent3";
    a3.online = true;
    a3.syn_targets = {t3};

    const auto snap = agg.aggregate({a1, a2, a3});

    EXPECT_EQ(snap.online_agents, 3u);
    ASSERT_EQ(snap.merged_syn_targets.size(), 1u);
    EXPECT_EQ(snap.merged_syn_targets[0].syn_count, 135u);
    EXPECT_EQ(snap.merged_syn_targets[0].syn_ack_count, 6u);
    EXPECT_DOUBLE_EQ(snap.merged_syn_targets[0].syn_rate_pps, 135.0);

    ASSERT_EQ(snap.alerts.size(), 1u);
    const auto& al = snap.alerts[0];
    EXPECT_EQ(al.type, DistributedAlertType::DistributedSynFlood);
    EXPECT_EQ(al.severity, DistributedAlertSeverity::Critical);
    EXPECT_EQ(al.target_ip, victim_ip);
    EXPECT_EQ(al.target_port, victim_port);
    EXPECT_EQ(al.contributing_agents, 3u);
    EXPECT_DOUBLE_EQ(al.combined_rate_pps, 135.0);
    EXPECT_NEAR(al.metric_ratio, 6.0 / 135.0, 1e-6);
}

TEST(DistributedAggregatorTest, HighSynAckRatioSuppressesDistributedSynFloodAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 3;
    cfg.global_syn_pps_threshold = 100.0;
    cfg.max_syn_ack_ratio = 0.25;
    DistributedAggregator agg{cfg};

    const auto victim_ip = make_ip(10, 0, 0, 50);
    const uint16_t victim_port = 443;

    SynTargetEntry t1{victim_ip, victim_port, 60, 55, 60.0};
    SynTargetEntry t2{victim_ip, victim_port, 60, 55, 60.0};
    SynTargetEntry t3{victim_ip, victim_port, 60, 55, 60.0};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.syn_targets = {t1};

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.syn_targets = {t2};

    AgentMetricsReport a3{};
    a3.agent_id = "a3";
    a3.syn_targets = {t3};

    const auto snap = agg.aggregate({a1, a2, a3});

    ASSERT_EQ(snap.merged_syn_targets.size(), 1u);
    EXPECT_EQ(snap.merged_syn_targets[0].syn_count, 180u);
    EXPECT_EQ(snap.merged_syn_targets[0].syn_ack_count, 165u);
    EXPECT_TRUE(snap.alerts.empty());
}

TEST(DistributedAggregatorTest, SingleAgentAboveThresholdDoesNotTriggerDistributedAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_syn_pps_threshold = 100.0;
    cfg.max_syn_ack_ratio = 0.25;
    DistributedAggregator agg{cfg};

    const auto victim_ip = make_ip(10, 0, 0, 50);
    const uint16_t victim_port = 443;

    SynTargetEntry t1{victim_ip, victim_port, 500, 10, 500.0};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.syn_targets = {t1};

    AgentMetricsReport a2{};
    a2.agent_id = "a2";

    const auto snap = agg.aggregate({a1, a2});

    ASSERT_EQ(snap.merged_syn_targets.size(), 1u);
    EXPECT_TRUE(snap.alerts.empty());
}

TEST(DistributedAggregatorTest, DistributedVolumetricUdpFloodTriggersAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_volumetric_pps_threshold = 500.0;
    cfg.protocol_dominance_ratio = 0.70;
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.total_packets = 300;
    a1.interval.valid = true;
    a1.interval.packets = 300;
    a1.interval.pps = 300.0;
    a1.interval.udp = 255;
    a1.interval.tcp = 45;

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.total_packets = 300;
    a2.interval.valid = true;
    a2.interval.packets = 300;
    a2.interval.pps = 300.0;
    a2.interval.udp = 255;
    a2.interval.tcp = 45;

    const auto snap = agg.aggregate({a1, a2});

    EXPECT_DOUBLE_EQ(snap.global_pps, 600.0);
    EXPECT_EQ(snap.interval_udp, 510u);
    EXPECT_EQ(snap.interval_packets, 600u);

    ASSERT_EQ(snap.alerts.size(), 1u);
    const auto& al = snap.alerts[0];
    EXPECT_EQ(al.type, DistributedAlertType::DistributedVolumetricFlood);
    EXPECT_EQ(al.severity, DistributedAlertSeverity::Critical);
    EXPECT_EQ(al.contributing_agents, 2u);
    EXPECT_DOUBLE_EQ(al.combined_rate_pps, 600.0);
    EXPECT_DOUBLE_EQ(al.metric_ratio, 510.0 / 600.0);
}

TEST(DistributedAggregatorTest, DistributedVolumetricIcmpFloodTriggersAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_volumetric_pps_threshold = 500.0;
    cfg.protocol_dominance_ratio = 0.70;
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.total_packets = 400;
    a1.interval.valid = true;
    a1.interval.packets = 400;
    a1.interval.pps = 400.0;
    a1.interval.icmp = 350;

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.total_packets = 400;
    a2.interval.valid = true;
    a2.interval.packets = 400;
    a2.interval.pps = 400.0;
    a2.interval.icmp = 350;

    const auto snap = agg.aggregate({a1, a2});

    ASSERT_EQ(snap.alerts.size(), 1u);
    EXPECT_EQ(snap.alerts[0].type, DistributedAlertType::DistributedVolumetricFlood);
    EXPECT_NEAR(snap.alerts[0].metric_ratio, 700.0 / 800.0, 1e-6);
}

TEST(DistributedAggregatorTest, DistributedTargetPortConcentrationTriggersAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_volumetric_pps_threshold = 500.0;
    cfg.target_port_concentration_ratio = 0.60;
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.total_packets = 400;
    a1.top_ports = {PortEntry{80, 260, 26000}, PortEntry{443, 140, 14000}};
    a1.interval.valid = true;
    a1.interval.packets = 400;
    a1.interval.pps = 400.0;
    a1.interval.port_deltas = {PortEntry{80, 260, 26000}, PortEntry{443, 140, 14000}};

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.total_packets = 400;
    a2.top_ports = {PortEntry{80, 260, 26000}, PortEntry{443, 140, 14000}};
    a2.interval.valid = true;
    a2.interval.packets = 400;
    a2.interval.pps = 400.0;
    a2.interval.port_deltas = {PortEntry{80, 260, 26000}, PortEntry{443, 140, 14000}};

    const auto snap = agg.aggregate({a1, a2});

    ASSERT_EQ(snap.alerts.size(), 1u);
    const auto& al = snap.alerts[0];
    EXPECT_EQ(al.type, DistributedAlertType::DistributedTargetConcentration);
    EXPECT_EQ(al.severity, DistributedAlertSeverity::Warning);
    EXPECT_EQ(al.target_port, 80u);
    EXPECT_EQ(al.contributing_agents, 2u);
    EXPECT_NEAR(al.metric_ratio, 520.0 / 800.0, 1e-6);
}

TEST(DistributedAggregatorTest, MergedTopTalkersAndTopPortsAreAggregatedAndBounded) {
    DistributedAggregatorConfig cfg{};
    cfg.top_k_limit = 2;
    DistributedAggregator agg{cfg};

    const auto ip1 = make_ip(10, 0, 0, 1);
    const auto ip2 = make_ip(10, 0, 0, 2);
    const auto ip3 = make_ip(10, 0, 0, 3);

    AgentMetricsReport a1{};
    a1.top_talkers = {
        TalkerEntry{ip1, 100, 1000},
        TalkerEntry{ip2, 50, 500}
    };
    a1.top_ports = {
        PortEntry{80, 100, 1000},
        PortEntry{443, 50, 500}
    };

    AgentMetricsReport a2{};
    a2.top_talkers = {
        TalkerEntry{ip2, 60, 600},
        TalkerEntry{ip3, 200, 2000}
    };
    a2.top_ports = {
        PortEntry{443, 70, 700},
        PortEntry{53, 200, 2000}
    };

    const auto snap = agg.aggregate({a1, a2});

    ASSERT_EQ(snap.merged_top_talkers.size(), 2u);
    EXPECT_EQ(snap.merged_top_talkers[0].ip, ip3);
    EXPECT_EQ(snap.merged_top_talkers[0].bytes, 2000u);
    EXPECT_EQ(snap.merged_top_talkers[1].ip, ip2);
    EXPECT_EQ(snap.merged_top_talkers[1].bytes, 1100u);

    ASSERT_EQ(snap.merged_top_ports.size(), 2u);
    EXPECT_EQ(snap.merged_top_ports[0].port, 53u);
    EXPECT_EQ(snap.merged_top_ports[0].bytes, 2000u);
    EXPECT_EQ(snap.merged_top_ports[1].port, 443u);
    EXPECT_EQ(snap.merged_top_ports[1].bytes, 1200u);
}

TEST(DistributedAggregatorTest, PartialAgentOutageContinuesEvaluatingOnlineAgents) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_syn_pps_threshold = 100.0;
    cfg.max_syn_ack_ratio = 0.25;
    DistributedAggregator agg{cfg};

    const auto victim_ip = make_ip(10, 0, 0, 50);

    AgentMetricsReport a1{};
    a1.agent_id = "agent1";
    a1.online = true;
    a1.syn_targets = {SynTargetEntry{victim_ip, 443, 60, 2, 60.0}};

    AgentMetricsReport a2{};
    a2.agent_id = "agent2";
    a2.online = true;
    a2.syn_targets = {SynTargetEntry{victim_ip, 443, 60, 2, 60.0}};

    AgentMetricsReport a3{};
    a3.agent_id = "agent3_unreachable";
    a3.online = false;
    a3.error_message = "Connection refused";

    const auto snap = agg.aggregate({a1, a2, a3});

    EXPECT_EQ(snap.total_agents, 3u);
    EXPECT_EQ(snap.online_agents, 2u);
    ASSERT_EQ(snap.alerts.size(), 1u);
    EXPECT_EQ(snap.alerts[0].contributing_agents, 2u);
    EXPECT_DOUBLE_EQ(snap.alerts[0].combined_rate_pps, 120.0);
}

TEST(DistributedAggregatorTest, SpikeAfterQuietPeriodTriggersVolumetricAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_volumetric_pps_threshold = 500.0;
    cfg.protocol_dominance_ratio = 0.70;
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.total_packets = 37600;
    a1.pps = 10.4;
    a1.interval.valid = true;
    a1.interval.pps = 800.0;
    a1.interval.packets = 1600;
    a1.interval.udp = 1500;

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.total_packets = 37600;
    a2.pps = 10.4;
    a2.interval.valid = true;
    a2.interval.pps = 800.0;
    a2.interval.packets = 1600;
    a2.interval.udp = 1500;

    const auto snap = agg.aggregate({a1, a2});

    EXPECT_DOUBLE_EQ(snap.global_pps, 1600.0);
    EXPECT_EQ(snap.interval_packets, 3200u);
    EXPECT_EQ(snap.interval_udp, 3000u);

    ASSERT_EQ(snap.alerts.size(), 1u);
    EXPECT_EQ(snap.alerts[0].type, DistributedAlertType::DistributedVolumetricFlood);
    EXPECT_DOUBLE_EQ(snap.alerts[0].combined_rate_pps, 1600.0);
    EXPECT_DOUBLE_EQ(snap.alerts[0].metric_ratio, 3000.0 / 3200.0);
}

TEST(DistributedAggregatorTest, EndedAttackWithHighCumulativeUdpDoesNotTriggerAlert) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_volumetric_pps_threshold = 500.0;
    cfg.protocol_dominance_ratio = 0.70;
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.total_packets = 50000;
    a1.udp_packets = 40000;
    a1.interval.valid = true;
    a1.interval.pps = 10.0;
    a1.interval.packets = 20;
    a1.interval.udp = 2;

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.total_packets = 50000;
    a2.udp_packets = 40000;
    a2.interval.valid = true;
    a2.interval.pps = 10.0;
    a2.interval.packets = 20;
    a2.interval.udp = 2;

    const auto snap = agg.aggregate({a1, a2});

    EXPECT_DOUBLE_EQ(snap.global_pps, 20.0);
    EXPECT_TRUE(snap.alerts.empty());
}

TEST(DistributedAggregatorTest, DnsWitnessNotCountedIfZeroIntervalUdp) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_volumetric_pps_threshold = 500.0;
    cfg.protocol_dominance_ratio = 0.70;
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.interval.valid = true;
    a1.interval.pps = 600.0;
    a1.interval.packets = 600;
    a1.interval.udp = 550;

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.udp_packets = 50;
    a2.interval.valid = true;
    a2.interval.pps = 100.0;
    a2.interval.packets = 100;
    a2.interval.udp = 0;

    const auto snap = agg.aggregate({a1, a2});

    EXPECT_TRUE(snap.alerts.empty());
}

TEST(DistributedAggregatorTest, InvalidIntervalAgentIncludedInOnlineNotInterval) {
    DistributedAggregatorConfig cfg{};
    DistributedAggregator agg{cfg};

    AgentMetricsReport a1{};
    a1.agent_id = "a1";
    a1.online = true;
    a1.total_packets = 100;
    a1.interval.valid = true;
    a1.interval.pps = 50.0;
    a1.interval.bps = 5000.0;
    a1.interval.packets = 100;

    AgentMetricsReport a2{};
    a2.agent_id = "a2";
    a2.online = true;
    a2.total_packets = 200;
    a2.interval.valid = false;
    a2.interval.pps = 999.0;
    a2.interval.packets = 200;

    const auto snap = agg.aggregate({a1, a2});

    EXPECT_EQ(snap.total_agents, 2u);
    EXPECT_EQ(snap.online_agents, 2u);
    EXPECT_EQ(snap.interval_agents, 1u);
    EXPECT_EQ(snap.total_packets, 300u);
    EXPECT_EQ(snap.interval_packets, 100u);
    EXPECT_DOUBLE_EQ(snap.global_pps, 50.0);
    EXPECT_DOUBLE_EQ(snap.global_bps, 5000.0);
}

TEST(DistributedAggregatorTest, SameFlowSeenByTwoAgentsIsCountedTwice_DocumentedAssumption) {
    DistributedAggregatorConfig cfg{};
    cfg.min_agents = 2;
    cfg.global_syn_pps_threshold = 100.0;
    cfg.max_syn_ack_ratio = 0.25;
    DistributedAggregator agg{cfg};

    const auto victim_ip = make_ip(192, 168, 1, 100);
    const uint16_t victim_port = 80;

    SynTargetEntry target{victim_ip, victim_port, 60, 2, 60.0};

    AgentMetricsReport a1{};
    a1.agent_id = "agent_tap1";
    a1.online = true;
    a1.syn_targets = {target};

    AgentMetricsReport a2{};
    a2.agent_id = "agent_tap2";
    a2.online = true;
    a2.syn_targets = {target};

    const auto snap = agg.aggregate({a1, a2});

    ASSERT_EQ(snap.alerts.size(), 1u);
    EXPECT_EQ(snap.alerts[0].contributing_agents, 2u);
    EXPECT_DOUBLE_EQ(snap.alerts[0].combined_rate_pps, 120.0);
}