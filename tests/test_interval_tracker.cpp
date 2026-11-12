#include "netsight/analytics/IntervalTracker.hpp"
#include "netsight/export/JsonSerializer.hpp"

#include <gtest/gtest.h>
#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using namespace netsight;

TEST(IntervalTrackerTest, FirstObservationTakesFullHistoryAsBaseline) {
    IntervalTracker tracker(64);

    AgentMetricsReport report{};
    report.agent_id = "agent-1";
    report.online = true;
    report.total_packets = 1000;
    report.total_wire_bytes = 100000;
    report.capture_duration_seconds = 10.0;
    report.udp_packets = 800;

    std::vector<AgentMetricsReport> reports = {report};
    tracker.annotate(reports);

    ASSERT_EQ(reports.size(), 1u);
    EXPECT_TRUE(reports[0].interval.valid);
    EXPECT_FALSE(reports[0].interval.counter_reset);
    EXPECT_EQ(reports[0].interval.packets, 1000u);
    EXPECT_EQ(reports[0].interval.wire_bytes, 100000u);
    EXPECT_DOUBLE_EQ(reports[0].interval.seconds, 10.0);
    EXPECT_DOUBLE_EQ(reports[0].interval.pps, 100.0);
    EXPECT_DOUBLE_EQ(reports[0].interval.bps, 10000.0);
    EXPECT_EQ(reports[0].interval.udp, 800u);
}

TEST(IntervalTrackerTest, SecondRoundComputesIntervalDeltaAndPps) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 36000;
    r1.total_wire_bytes = 3600000;
    r1.capture_duration_seconds = 3600.0;
    r1.udp_packets = 1000;

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-1";
    r2.online = true;
    r2.total_packets = 37600;
    r2.total_wire_bytes = 3760000;
    r2.capture_duration_seconds = 3602.0;
    r2.udp_packets = 2500;

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);

    ASSERT_EQ(batch2.size(), 1u);
    EXPECT_TRUE(batch2[0].interval.valid);
    EXPECT_FALSE(batch2[0].interval.counter_reset);
    EXPECT_DOUBLE_EQ(batch2[0].interval.seconds, 2.0);
    EXPECT_EQ(batch2[0].interval.packets, 1600u);
    EXPECT_EQ(batch2[0].interval.wire_bytes, 160000u);
    EXPECT_DOUBLE_EQ(batch2[0].interval.pps, 800.0);
    EXPECT_DOUBLE_EQ(batch2[0].interval.bps, 80000.0);
    EXPECT_EQ(batch2[0].interval.udp, 1500u);
}

TEST(IntervalTrackerTest, CounterResetWhenPacketsOrDurationDrop) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 1000;
    r1.capture_duration_seconds = 50.0;

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-1";
    r2.online = true;
    r2.total_packets = 200;
    r2.capture_duration_seconds = 10.0;
    r2.udp_packets = 150;

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);

    ASSERT_EQ(batch2.size(), 1u);
    EXPECT_TRUE(batch2[0].interval.valid);
    EXPECT_TRUE(batch2[0].interval.counter_reset);
    EXPECT_EQ(batch2[0].interval.packets, 200u);
    EXPECT_DOUBLE_EQ(batch2[0].interval.seconds, 10.0);
    EXPECT_EQ(batch2[0].interval.udp, 150u);
    EXPECT_DOUBLE_EQ(batch2[0].interval.pps, 20.0);
}

TEST(IntervalTrackerTest, OfflineAgentRoundDoesNotAdvanceBaseline) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 100;
    r1.capture_duration_seconds = 10.0;

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-1";
    r2.online = false;
    r2.total_packets = 500;
    r2.capture_duration_seconds = 20.0;

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);

    AgentMetricsReport r3{};
    r3.agent_id = "agent-1";
    r3.online = true;
    r3.total_packets = 300;
    r3.capture_duration_seconds = 30.0;

    std::vector<AgentMetricsReport> batch3 = {r3};
    tracker.annotate(batch3);

    ASSERT_EQ(batch3.size(), 1u);
    EXPECT_TRUE(batch3[0].interval.valid);
    EXPECT_EQ(batch3[0].interval.packets, 200u);
    EXPECT_DOUBLE_EQ(batch3[0].interval.seconds, 20.0);
    EXPECT_DOUBLE_EQ(batch3[0].interval.pps, 10.0);
}

TEST(IntervalTrackerTest, QuietAgentWithZeroDeltaTimeAndZeroPacketsIsValid) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 50;
    r1.capture_duration_seconds = 10.0;

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-1";
    r2.online = true;
    r2.total_packets = 50;
    r2.capture_duration_seconds = 10.0;

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);

    ASSERT_EQ(batch2.size(), 1u);
    EXPECT_TRUE(batch2[0].interval.valid);
    EXPECT_EQ(batch2[0].interval.packets, 0u);
    EXPECT_DOUBLE_EQ(batch2[0].interval.seconds, 0.0);
    EXPECT_DOUBLE_EQ(batch2[0].interval.pps, 0.0);
    EXPECT_DOUBLE_EQ(batch2[0].interval.bps, 0.0);
}

TEST(IntervalTrackerTest, ZeroDeltaTimeWithPositivePacketsIsInvalid) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 50;
    r1.capture_duration_seconds = 10.0;

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-1";
    r2.online = true;
    r2.total_packets = 100;
    r2.capture_duration_seconds = 10.0;

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);

    ASSERT_EQ(batch2.size(), 1u);
    EXPECT_FALSE(batch2[0].interval.valid);
}

TEST(IntervalTrackerTest, ExceedingMaxAgentsRejectsNewAgents) {
    IntervalTracker tracker(2);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 10;
    r1.capture_duration_seconds = 1.0;

    AgentMetricsReport r2{};
    r2.agent_id = "agent-2";
    r2.online = true;
    r2.total_packets = 10;
    r2.capture_duration_seconds = 1.0;

    AgentMetricsReport r3{};
    r3.agent_id = "agent-3";
    r3.online = true;
    r3.total_packets = 10;
    r3.capture_duration_seconds = 1.0;

    std::vector<AgentMetricsReport> reports = {r1, r2, r3};
    tracker.annotate(reports);

    EXPECT_TRUE(reports[0].interval.valid);
    EXPECT_TRUE(reports[1].interval.valid);
    EXPECT_FALSE(reports[2].interval.valid);

    EXPECT_EQ(tracker.tracked_agents(), 2u);
    EXPECT_EQ(tracker.rejected_agents(), 1u);
}

TEST(IntervalTrackerTest, PortNewlyEnteringTopKIsSkippedInPortDeltas) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 100;
    r1.capture_duration_seconds = 1.0;
    r1.top_ports = {PortEntry{80, 100, 1000}};

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-1";
    r2.online = true;
    r2.total_packets = 250;
    r2.capture_duration_seconds = 2.0;
    r2.top_ports = {
        PortEntry{80, 150, 1500},
        PortEntry{443, 100, 1000}
    };

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);

    ASSERT_EQ(batch2[0].interval.port_deltas.size(), 1u);
    EXPECT_EQ(batch2[0].interval.port_deltas[0].port, 80u);
    EXPECT_EQ(batch2[0].interval.port_deltas[0].packets, 50u);
}

TEST(IntervalTrackerTest, NegativeOrNanCaptureDurationMarksIntervalInvalid) {
    IntervalTracker tracker(64);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 100;
    r1.capture_duration_seconds = -5.0;

    std::vector<AgentMetricsReport> batch1 = {r1};
    tracker.annotate(batch1);
    EXPECT_FALSE(batch1[0].interval.valid);

    AgentMetricsReport r2{};
    r2.agent_id = "agent-2";
    r2.online = true;
    r2.total_packets = 100;
    r2.capture_duration_seconds = std::numeric_limits<double>::quiet_NaN();

    std::vector<AgentMetricsReport> batch2 = {r2};
    tracker.annotate(batch2);
    EXPECT_FALSE(batch2[0].interval.valid);
}

TEST(IntervalTrackerTest, ResetClearsAllTrackedAndRejectedAgents) {
    IntervalTracker tracker(1);

    AgentMetricsReport r1{};
    r1.agent_id = "agent-1";
    r1.online = true;
    r1.total_packets = 10;
    r1.capture_duration_seconds = 1.0;

    AgentMetricsReport r2{};
    r2.agent_id = "agent-2";
    r2.online = true;
    r2.total_packets = 10;
    r2.capture_duration_seconds = 1.0;

    std::vector<AgentMetricsReport> batch = {r1, r2};
    tracker.annotate(batch);

    EXPECT_EQ(tracker.tracked_agents(), 1u);
    EXPECT_EQ(tracker.rejected_agents(), 1u);

    tracker.reset();
    EXPECT_EQ(tracker.tracked_agents(), 0u);
    EXPECT_EQ(tracker.rejected_agents(), 0u);
}

TEST(IntervalTrackerTest, ParseAgentStatsJsonWithIcmpv6AndArrayLimit256) {
    nlohmann::json j;
    j["totals"]["packets"] = 200;
    j["totals"]["duration_seconds"] = 10.0;
    j["l4"]["icmp"]["packets"] = 15;
    j["l4"]["icmpv6"]["packets"] = 25;

    nlohmann::json ports_arr = nlohmann::json::array();
    for (int i = 0; i < 300; ++i) {
        ports_arr.push_back({{"port", i + 1}, {"packets", 10}, {"bytes", 100}});
    }
    j["top_ports"] = ports_arr;

    AgentMetricsReport report{};
    EXPECT_TRUE(parse_agent_stats_json(j.dump(), report));

    EXPECT_DOUBLE_EQ(report.capture_duration_seconds, 10.0);
    EXPECT_EQ(report.icmp_packets, 40u);
    EXPECT_EQ(report.top_ports.size(), 256u);
}