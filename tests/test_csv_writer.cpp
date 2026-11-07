#include <gtest/gtest.h>
#include <fstream>
#include <iterator>
#include <locale>
#include <sstream>
#include <string>

#include "netsight/export/CsvWriter.hpp"
#include "support/TempFile.hpp"

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

TEST(CsvWriterTest, HeaderWrittenOnConstruction) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss);

    EXPECT_EQ(oss.str(), "interval_start,packets,bytes,tcp_packets,udp_packets,icmp_packets,other_packets,parse_errors,dropped,active_alerts\r\n");
    EXPECT_EQ(writer.rows_written(), 0);
    EXPECT_TRUE(writer.ok());
}

TEST(CsvWriterTest, SameIntervalDoesNotCloseRow) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'200'000}));
    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'500'000}));
    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'999'999}));
    EXPECT_EQ(writer.rows_written(), 0);
}

TEST(CsvWriterTest, NextIntervalClosesRowWithDeltas) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'200'000}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{2'100'000}));

    StatsSnapshot snap1{};
    snap1.total_packets = 3;
    snap1.total_wire_bytes = 300;
    writer.write_row(snap1);

    StatsSnapshot snap2{};
    snap2.total_packets = 5;
    snap2.total_wire_bytes = 500;
    writer.write_row(snap2);

    EXPECT_EQ(writer.rows_written(), 2);

    const std::string csv = oss.str();
    EXPECT_NE(csv.find("1970-01-01T00:00:01.000000Z,3,300,"), std::string::npos);
    EXPECT_NE(csv.find("1970-01-01T00:00:02.000000Z,2,200,"), std::string::npos);
}

TEST(CsvWriterTest, IntervalStartIsAlignedPacketTime) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'700'000'000'700'000LL}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{1'700'000'001'100'000LL}));

    StatsSnapshot snap{};
    snap.total_packets = 1;
    writer.write_row(snap);

    const std::string csv = oss.str();
    EXPECT_NE(csv.find("2023-11-14T22:13:20.000000Z,1,"), std::string::npos);
}

TEST(CsvWriterTest, GapsAreNotFilled) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'200'000}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{10'500'000}));

    StatsSnapshot s1{};
    s1.total_packets = 2;
    writer.write_row(s1);

    StatsSnapshot s2{};
    s2.total_packets = 3;
    writer.write_row(s2);

    EXPECT_EQ(writer.rows_written(), 2);

    const std::string csv = oss.str();
    EXPECT_NE(csv.find("1970-01-01T00:00:01.000000Z"), std::string::npos);
    EXPECT_NE(csv.find("1970-01-01T00:00:10.000000Z"), std::string::npos);
    EXPECT_EQ(csv.find("1970-01-01T00:00:02.000000Z"), std::string::npos);
}

TEST(CsvWriterTest, HugeTimeJumpProducesBoundedOutput) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'000'000}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{1'000'000 + 50LL * 365 * 86400 * 1'000'000}));

    StatsSnapshot s1{};
    writer.write_row(s1);
    writer.write_row(s1);

    EXPECT_EQ(writer.rows_written(), 2);
}

TEST(CsvWriterTest, OutOfOrderPacketStaysInCurrentInterval) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{2'400'000}));
    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'800'000}));
    EXPECT_EQ(writer.rows_written(), 0);
}

TEST(CsvWriterTest, NonPositiveTimestampsIgnored) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{0}));
    EXPECT_FALSE(writer.starts_new_interval(Timestamp{-5'000'000}));
    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'500'000}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{2'500'000}));
}

TEST(CsvWriterTest, CounterResetDoesNotUnderflow) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'000'000}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{2'000'000}));

    StatsSnapshot s1{};
    s1.total_packets = 1000;
    writer.write_row(s1);

    StatsSnapshot s2{};
    s2.total_packets = 10;
    writer.write_row(s2);

    const std::string csv = oss.str();
    EXPECT_EQ(csv.find("1844674407370955"), std::string::npos);
    EXPECT_NE(csv.find(",10,"), std::string::npos);
}

TEST(CsvWriterTest, ActiveAlertsIsGauge) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'000'000}));
    EXPECT_TRUE(writer.starts_new_interval(Timestamp{2'000'000}));

    StatsSnapshot s{};
    Alert a1{};
    a1.state = AlertState::Active;
    Alert a2{};
    a2.state = AlertState::Active;
    Alert a3{};
    a3.state = AlertState::Resolved;
    s.alerts = {a1, a2, a3};

    writer.write_row(s);
    writer.write_row(s);

    const std::string csv = oss.str();
    EXPECT_NE(csv.find(",2\r\n"), std::string::npos);
    EXPECT_EQ(csv.find(",0\r\n"), std::string::npos);
}

TEST(CsvWriterTest, FinalWriteIsIdempotent) {
    std::ostringstream oss;
    TimeSeriesCsvWriter writer(oss, Timestamp{1'000'000});

    EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'000'000}));
    StatsSnapshot s{};
    s.total_packets = 1;

    writer.write_row(s);
    EXPECT_EQ(writer.rows_written(), 1);

    writer.write_row(s);
    EXPECT_EQ(writer.rows_written(), 1);

    std::ostringstream empty_oss;
    TimeSeriesCsvWriter empty_writer(empty_oss);
    empty_writer.write_row(s);
    EXPECT_EQ(empty_writer.rows_written(), 0);
    EXPECT_EQ(empty_oss.str(), "interval_start,packets,bytes,tcp_packets,udp_packets,icmp_packets,other_packets,parse_errors,dropped,active_alerts\r\n");
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

TEST(CsvWriterTest, FileIsCrlfAndFlushedPerRow) {
    netsight::test::TempFile tmp("netsight_csv_", ".csv");
    {
        std::ofstream ofs(tmp.path(), std::ios::binary);
        ASSERT_TRUE(ofs.is_open());
        TimeSeriesCsvWriter writer(ofs, Timestamp{1'000'000});

        EXPECT_FALSE(writer.starts_new_interval(Timestamp{1'000'000}));
        EXPECT_TRUE(writer.starts_new_interval(Timestamp{2'000'000}));
        StatsSnapshot s1{};
        s1.total_packets = 1;
        writer.write_row(s1);

        EXPECT_TRUE(writer.starts_new_interval(Timestamp{3'000'000}));
        StatsSnapshot s2{};
        s2.total_packets = 2;
        writer.write_row(s2);

        std::ifstream ifs(tmp.path(), std::ios::binary);
        ASSERT_TRUE(ifs.is_open());
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

        EXPECT_EQ(writer.rows_written(), 2);
        EXPECT_EQ(content.find("\r\r\n"), std::string::npos);

        std::size_t crlf_count = 0;
        std::string::size_type pos = 0;
        while ((pos = content.find("\r\n", pos)) != std::string::npos) {
            ++crlf_count;
            pos += 2;
        }
        EXPECT_EQ(crlf_count, 3);
    }
}

TEST(CsvWriterTest, FailedStreamNeverThrows) {
    std::ostringstream oss;
    oss.setstate(std::ios::badbit);
    StatsSnapshot snap{};

    EXPECT_NO_THROW(write_summary_csv(oss, snap));
}