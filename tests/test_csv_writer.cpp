#include <gtest/gtest.h>
#include <locale>
#include <sstream>
#include <string>

#include "netsight/export/CsvWriter.hpp"

using namespace netsight;

struct CommaNumPunct : std::numpunct<char> {
protected:
    char do_decimal_point() const override { return ','; }
    char do_thousands_sep() const override { return '.'; }
    std::string do_grouping() const override { return "\3"; }
};

TEST(CsvWriterTest, EscapeLeavesPlainFieldsUntouched) {
    EXPECT_EQ(csv_escape("10.0.0.1"), "10.0.0.1");
    EXPECT_EQ(csv_escape("2001:db8::1"), "2001:db8::1");
    EXPECT_EQ(csv_escape(""), "");
}

TEST(CsvWriterTest, EscapeQuotesSpecialCharacters) {
    EXPECT_EQ(csv_escape("a,b"), "\"a,b\"");
    EXPECT_EQ(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    EXPECT_EQ(csv_escape("l1\nl2"), "\"l1\nl2\"");
    EXPECT_EQ(csv_escape("x\r"), "\"x\r\"");
}

TEST(CsvWriterTest, NumbersAreLocaleIndependent) {
    std::ostringstream oss;
    oss.imbue(std::locale(oss.getloc(), new CommaNumPunct()));

    StatsSnapshot snap{};
    snap.total_packets = 10;
    snap.total_wire_bytes = 1234567;
    snap.packets_per_second = 4550.0;

    write_summary_csv(oss, snap);
    const std::string csv = oss.str();

    EXPECT_NE(csv.find("totals,,wire_bytes,1234567\r\n"), std::string::npos);
    EXPECT_NE(csv.find("totals,,packets_per_second,4550.000\r\n"), std::string::npos);
}

TEST(CsvWriterTest, SummaryContainsAllSections) {
    std::ostringstream oss;
    StatsSnapshot snap{};
    snap.total_packets = 100;
    snap.total_wire_bytes = 10000;
    snap.status.ok = 100;
    snap.l3.ipv4.packets = 90;
    snap.l3.ipv4.bytes = 9000;
    snap.l4.tcp.packets = 80;
    snap.l4.tcp.bytes = 8000;
    snap.drops.queue_dropped = 2;

    const auto ip1 = parse_ip_address("10.0.0.1");
    ASSERT_TRUE(ip1.has_value());
    snap.top_talkers.push_back({*ip1, 50, 5000});
    snap.top_ports.push_back({80, 50, 5000});

    const auto attacker = parse_ip_address("10.0.0.2");
    ASSERT_TRUE(attacker.has_value());

    Alert a{};
    a.id = 1;
    a.type = AlertType::PortScan;
    a.state = AlertState::Active;
    a.src_ip = *attacker;
    a.dst_ip = *ip1;
    a.dst_port = 80;
    a.started_at = Timestamp{100};
    a.last_seen_at = Timestamp{200};
    a.ended_at = Timestamp{0};
    snap.alerts.push_back(a);

    write_summary_csv(oss, snap);
    const std::string res = oss.str();

    EXPECT_NE(res.find("section,item,metric,value\r\n"), std::string::npos);
    EXPECT_NE(res.find("totals,,packets,100\r\n"), std::string::npos);
    EXPECT_NE(res.find("parse,,ok,100\r\n"), std::string::npos);
    EXPECT_NE(res.find("l3,ipv4,packets,90\r\n"), std::string::npos);
    EXPECT_NE(res.find("l4,tcp,packets,80\r\n"), std::string::npos);
    EXPECT_NE(res.find("drops,,queue_dropped,2\r\n"), std::string::npos);
    EXPECT_NE(res.find("top_talkers,1,ip,10.0.0.1\r\n"), std::string::npos);
    EXPECT_NE(res.find("top_ports,1,port,80\r\n"), std::string::npos);
    EXPECT_NE(res.find("alerts,1,type,port_scan\r\n"), std::string::npos);
    EXPECT_NE(res.find("alerts,1,state,active\r\n"), std::string::npos);
    EXPECT_NE(res.find("alerts,1,ended_at,\r\n"), std::string::npos);
}

TEST(CsvWriterTest, SummaryEscapesMeta) {
    std::ostringstream oss;
    StatsSnapshot snap{};
    const CsvMeta meta = {{"source", R"(C:\caps\a,b "x".pcap)"}};

    write_summary_csv(oss, snap, meta);
    const std::string res = oss.str();

    EXPECT_NE(res.find("meta,,source,\"C:\\caps\\a,b \"\"x\"\".pcap\"\r\n"), std::string::npos);
}

TEST(CsvWriterTest, SummaryWithoutPacketsHasEmptyTimestamps) {
    std::ostringstream oss;
    StatsSnapshot snap{};

    write_summary_csv(oss, snap);
    const std::string res = oss.str();

    EXPECT_NE(res.find("totals,,first_packet,\r\n"), std::string::npos);
    EXPECT_NE(res.find("totals,,last_packet,\r\n"), std::string::npos);
    EXPECT_EQ(res.find("1970-01-01"), std::string::npos);
}

TEST(CsvWriterTest, FailedStreamNeverThrows) {
    std::ostringstream oss;
    oss.setstate(std::ios::badbit);
    StatsSnapshot snap{};

    EXPECT_NO_THROW(write_summary_csv(oss, snap));
}