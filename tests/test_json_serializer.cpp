#include "netsight/export/JsonSerializer.hpp"

#include "netsight/core/IpAddress.hpp"

#include <gtest/gtest.h>
#include <limits>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace netsight;

TEST(JsonSerializerTest, ParseLimitAcceptsValidBounds) {
    EXPECT_EQ(parse_limit_param("1", 1000), std::optional<std::size_t>(1));
    EXPECT_EQ(parse_limit_param("10", 1000), std::optional<std::size_t>(10));
    EXPECT_EQ(parse_limit_param("1000", 1000), std::optional<std::size_t>(1000));
}

TEST(JsonSerializerTest, ParseLimitRejectsZeroNegativeOverflowAndGarbage) {
    EXPECT_EQ(parse_limit_param("", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("0", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("-1", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("+5", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param(" 5", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("5 ", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("10abc", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("1001", 1000), std::nullopt);
    EXPECT_EQ(parse_limit_param("999999999999999999999999999999", 1000), std::nullopt);
}

TEST(JsonSerializerTest, ParseAlertStateAcceptsExactValuesOnly) {
    EXPECT_EQ(parse_alert_state_param("all"), std::optional<AlertFilterState>(AlertFilterState::All));
    EXPECT_EQ(parse_alert_state_param("active"), std::optional<AlertFilterState>(AlertFilterState::Active));
    EXPECT_EQ(parse_alert_state_param("resolved"), std::optional<AlertFilterState>(AlertFilterState::Resolved));

    EXPECT_EQ(parse_alert_state_param(""), std::nullopt);
    EXPECT_EQ(parse_alert_state_param("ACTIVE"), std::nullopt);
    EXPECT_EQ(parse_alert_state_param("unknown"), std::nullopt);
    EXPECT_EQ(parse_alert_state_param("all "), std::nullopt);
}

TEST(JsonSerializerTest, HealthJsonContainsStatusVersionAndSeq) {
    std::string s = serialize_health_json("0.1.0", 42);
    auto j = json::parse(s);

    EXPECT_EQ(j["status"], "ok");
    EXPECT_EQ(j["version"], "0.1.0");
    EXPECT_EQ(j["snapshot_seq"], 42);
}

TEST(JsonSerializerTest, EmptySnapshotHasNullPacketTimestamps) {
    StatsSnapshot snap{};
    std::string s = serialize_stats_json(snap);
    auto j = json::parse(s);

    EXPECT_EQ(j["totals"]["packets"], 0);
    EXPECT_TRUE(j["totals"]["first_packet"].is_null());
    EXPECT_TRUE(j["totals"]["last_packet"].is_null());
    EXPECT_EQ(j["active_alerts"], 0);
}

TEST(JsonSerializerTest, PopulatedStatsSerializesAllCountersAndProtocols) {
    StatsSnapshot snap{};
    snap.snapshot_seq = 12;
    snap.total_packets = 100;
    snap.total_wire_bytes = 15000;
    snap.total_captured_bytes = 15000;
    snap.first_packet_ts = Timestamp{1700000000000000};
    snap.last_packet_ts = Timestamp{1700000003000000};
    snap.duration_seconds = 3.0;
    snap.packets_per_second = 33.3;
    snap.bytes_per_second = 5000.0;

    snap.status.ok = 98;
    snap.status.truncated = 2;

    snap.l3.ipv4.packets = 80;
    snap.l3.ipv4.bytes = 12000;
    snap.l3.ipv6.packets = 20;
    snap.l3.ipv6.bytes = 3000;
    snap.l3.vlan_tagged_packets = 5;

    snap.l4.tcp.packets = 70;
    snap.l4.tcp.bytes = 10000;
    snap.l4.udp.packets = 30;
    snap.l4.udp.bytes = 5000;

    snap.top_ports.push_back(PortEntry{443, 60, 9000});

    Alert a1{};
    a1.id = 1;
    a1.state = AlertState::Active;
    Alert a2{};
    a2.id = 2;
    a2.state = AlertState::Active;
    Alert a3{};
    a3.id = 3;
    a3.state = AlertState::Resolved;
    snap.alerts = {a1, a2, a3};

    std::string s = serialize_stats_json(snap);
    auto j = json::parse(s);

    EXPECT_EQ(j["snapshot_seq"], 12);
    EXPECT_EQ(j["totals"]["packets"], 100);
    EXPECT_FALSE(j["totals"]["first_packet"].is_null());
    EXPECT_FALSE(j["totals"]["last_packet"].is_null());
    EXPECT_EQ(j["parse"]["ok"], 98);
    EXPECT_EQ(j["parse"]["truncated"], 2);
    EXPECT_EQ(j["l3"]["ipv4"]["packets"], 80);
    EXPECT_EQ(j["l3"]["vlan_tagged_packets"], 5);
    EXPECT_EQ(j["l4"]["tcp"]["packets"], 70);
    ASSERT_EQ(j["top_ports"].size(), 1);
    EXPECT_EQ(j["top_ports"][0]["port"], 443);
    EXPECT_EQ(j["active_alerts"], 2);
}

TEST(JsonSerializerTest, NonFiniteDoublesSanitizedToZero) {
    StatsSnapshot snap{};
    snap.packets_per_second = std::numeric_limits<double>::quiet_NaN();
    snap.bytes_per_second = std::numeric_limits<double>::infinity();

    std::string s = serialize_stats_json(snap);
    auto j = json::parse(s);

    EXPECT_DOUBLE_EQ(j["totals"]["packets_per_second"].get<double>(), 0.0);
    EXPECT_DOUBLE_EQ(j["totals"]["bytes_per_second"].get<double>(), 0.0);
}

TEST(JsonSerializerTest, TopTalkersWithoutLimitReturnsAll) {
    StatsSnapshot snap{};
    snap.snapshot_seq = 5;
    const std::uint8_t ip1[4] = {10, 0, 0, 1};
    const std::uint8_t ip2[4] = {10, 0, 0, 2};
    const std::uint8_t ip3[4] = {10, 0, 0, 3};
    const std::uint8_t ip4[4] = {10, 0, 0, 4};

    snap.top_talkers = {
        TalkerEntry{IpAddress::from_ipv4(ip1), 10, 1000},
        TalkerEntry{IpAddress::from_ipv4(ip2), 8, 800},
        TalkerEntry{IpAddress::from_ipv4(ip3), 6, 600},
        TalkerEntry{IpAddress::from_ipv4(ip4), 4, 400}
    };

    std::string s = serialize_top_talkers_json(snap, std::nullopt);
    auto j = json::parse(s);

    EXPECT_EQ(j["count"], 4);
    EXPECT_EQ(j["total_available"], 4);
    ASSERT_EQ(j["talkers"].size(), 4);
    EXPECT_EQ(j["talkers"][0]["ip"], "10.0.0.1");
    EXPECT_EQ(j["talkers"][3]["ip"], "10.0.0.4");
}

TEST(JsonSerializerTest, TopTalkersAppliesLimitAndPreservesTotalAvailable) {
    StatsSnapshot snap{};
    const std::uint8_t ip1[4] = {192, 168, 1, 1};
    const std::uint8_t ip2[4] = {192, 168, 1, 2};
    const std::uint8_t ip3[4] = {192, 168, 1, 3};
    const std::uint8_t ip4[4] = {192, 168, 1, 4};

    snap.top_talkers = {
        TalkerEntry{IpAddress::from_ipv4(ip1), 10, 1000},
        TalkerEntry{IpAddress::from_ipv4(ip2), 8, 800},
        TalkerEntry{IpAddress::from_ipv4(ip3), 6, 600},
        TalkerEntry{IpAddress::from_ipv4(ip4), 4, 400}
    };

    std::string s = serialize_top_talkers_json(snap, 2);
    auto j = json::parse(s);

    EXPECT_EQ(j["count"], 2);
    EXPECT_EQ(j["total_available"], 4);
    ASSERT_EQ(j["talkers"].size(), 2);
    EXPECT_EQ(j["talkers"][0]["ip"], "192.168.1.1");
    EXPECT_EQ(j["talkers"][1]["ip"], "192.168.1.2");
}

TEST(JsonSerializerTest, TopTalkersLimitLargerThanSizeClampsCleanly) {
    StatsSnapshot snap{};
    const std::uint8_t ip1[4] = {1, 1, 1, 1};
    const std::uint8_t ip2[4] = {2, 2, 2, 2};

    snap.top_talkers = {
        TalkerEntry{IpAddress::from_ipv4(ip1), 10, 1000},
        TalkerEntry{IpAddress::from_ipv4(ip2), 8, 800}
    };

    std::string s = serialize_top_talkers_json(snap, 50);
    auto j = json::parse(s);

    EXPECT_EQ(j["count"], 2);
    EXPECT_EQ(j["total_available"], 2);
    EXPECT_EQ(j["talkers"].size(), 2);
}

TEST(JsonSerializerTest, AlertsInvalidIpAndActiveEndedAtBecomeNull) {
    StatsSnapshot snap{};
    const std::uint8_t dst_bytes[4] = {192, 168, 1, 10};
    const std::uint8_t src_bytes[4] = {10, 0, 0, 99};

    Alert a1{};
    a1.id = 1;
    a1.type = AlertType::SynFlood;
    a1.state = AlertState::Active;
    a1.src_ip = IpAddress{};
    a1.dst_ip = IpAddress::from_ipv4(dst_bytes);
    a1.dst_port = 443;
    a1.started_at = Timestamp{1000};
    a1.last_seen_at = Timestamp{2000};
    a1.ended_at = Timestamp{0};

    Alert a2{};
    a2.id = 2;
    a2.type = AlertType::PortScan;
    a2.state = AlertState::Resolved;
    a2.src_ip = IpAddress::from_ipv4(src_bytes);
    a2.dst_ip = IpAddress{};
    a2.started_at = Timestamp{1000};
    a2.last_seen_at = Timestamp{2000};
    a2.ended_at = Timestamp{3000};

    snap.alerts = {a1, a2};

    std::string s = serialize_alerts_json(snap, AlertFilterState::All, std::nullopt);
    auto j = json::parse(s);

    ASSERT_EQ(j["alerts"].size(), 2);

    EXPECT_TRUE(j["alerts"][0]["src_ip"].is_null());
    EXPECT_EQ(j["alerts"][0]["dst_ip"], "192.168.1.10");
    EXPECT_TRUE(j["alerts"][0]["ended_at"].is_null());
    EXPECT_EQ(j["alerts"][0]["type"], "syn_flood");
    EXPECT_EQ(j["alerts"][0]["state"], "active");

    EXPECT_EQ(j["alerts"][1]["src_ip"], "10.0.0.99");
    EXPECT_TRUE(j["alerts"][1]["dst_ip"].is_null());
    EXPECT_FALSE(j["alerts"][1]["ended_at"].is_null());
    EXPECT_EQ(j["alerts"][1]["type"], "port_scan");
    EXPECT_EQ(j["alerts"][1]["state"], "resolved");
}

TEST(JsonSerializerTest, AlertsFilterByStateAndLimit) {
    StatsSnapshot snap{};

    Alert a1{};
    a1.id = 1;
    a1.state = AlertState::Active;
    Alert a2{};
    a2.id = 2;
    a2.state = AlertState::Resolved;
    Alert a3{};
    a3.id = 3;
    a3.state = AlertState::Active;

    snap.alerts = {a1, a2, a3};

    std::string s = serialize_alerts_json(snap, AlertFilterState::Active, 1);
    auto j = json::parse(s);

    EXPECT_EQ(j["total_matching"], 2);
    EXPECT_EQ(j["count"], 1);
    ASSERT_EQ(j["alerts"].size(), 1);
    EXPECT_EQ(j["alerts"][0]["id"], 1);
}

TEST(JsonSerializerTest, DropsJsonContainsAllEightCounters) {
    StatsSnapshot snap{};
    snap.snapshot_seq = 9;
    snap.drops.filtered_out = 10;
    snap.drops.queue_dropped = 20;
    snap.drops.kernel_dropped = 30;
    snap.drops.interface_dropped = 40;
    snap.drops.untracked_talker_packets = 50;
    snap.drops.untracked_port_packets = 60;
    snap.drops.untracked_syn_targets = 70;
    snap.drops.untracked_scan_sources = 80;

    std::string s = serialize_drops_json(snap);
    auto j = json::parse(s);

    EXPECT_EQ(j["snapshot_seq"], 9);
    EXPECT_EQ(j["drops"]["filtered_out"], 10);
    EXPECT_EQ(j["drops"]["queue_dropped"], 20);
    EXPECT_EQ(j["drops"]["kernel_dropped"], 30);
    EXPECT_EQ(j["drops"]["interface_dropped"], 40);
    EXPECT_EQ(j["drops"]["untracked_talker_packets"], 50);
    EXPECT_EQ(j["drops"]["untracked_port_packets"], 60);
    EXPECT_EQ(j["drops"]["untracked_syn_targets"], 70);
    EXPECT_EQ(j["drops"]["untracked_scan_sources"], 80);
}

TEST(JsonSerializerTest, ErrorJsonEscapesSpecialCharactersAndInvalidUtf8) {
    std::string bad_msg = "Error with \"quotes\", \n newline and invalid byte \xFF";
    std::string s = serialize_error_json("test_error", bad_msg);

    json j;
    EXPECT_NO_THROW({
        j = json::parse(s);
    });

    EXPECT_EQ(j["error"]["code"], "test_error");
    EXPECT_TRUE(j["error"]["message"].is_string());
}