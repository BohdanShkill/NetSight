#include <gtest/gtest.h>

#include "Cli.hpp"

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

using namespace netsight;

TEST(CliTest, HelpAndVersionReturnZeroAndCommandNone) {
    for (const auto& flag : {"-h", "--help"}) {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({flag}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        EXPECT_EQ(res.command, CommandKind::None);
        EXPECT_FALSE(out.str().empty());
        EXPECT_TRUE(err.str().empty());
    }

    for (const auto& flag : {"-v", "--version"}) {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({flag}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        EXPECT_EQ(res.command, CommandKind::None);
        EXPECT_NE(out.str().find("netsight"), std::string::npos);
        EXPECT_TRUE(err.str().empty());
    }
}

TEST(CliTest, NoArgumentsReturnsUsageError) {
    std::ostringstream out;
    std::ostringstream err;
    auto res = parse_cli({}, out, err);
    EXPECT_EQ(res.exit_code, ExitCode::UsageError);
    EXPECT_EQ(res.command, CommandKind::None);
    EXPECT_FALSE(err.str().empty());
}

TEST(CliTest, UnknownSubcommandOrFlagReturnsUsageError) {
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"foo"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "--bogus"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(CliTest, ParsesListSubcommand) {
    std::ostringstream out;
    std::ostringstream err;
    auto res = parse_cli({"list"}, out, err);
    EXPECT_EQ(res.exit_code, ExitCode::Ok);
    EXPECT_EQ(res.command, CommandKind::List);
    EXPECT_TRUE(err.str().empty());
}

TEST(CliTest, MutuallyExclusiveInterfaceAndReadFile) {
    std::ostringstream out;
    std::ostringstream err;
    auto res = parse_cli({"capture", "-i", "eth0", "-r", "a.pcap"}, out, err);
    EXPECT_EQ(res.exit_code, ExitCode::UsageError);
    EXPECT_FALSE(err.str().empty());
}

TEST(CliTest, BpfSnaplenAndNoPromiscRejectedWithReadFile) {
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--bpf", "tcp"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--snaplen", "128"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--no-promisc"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(CliTest, ValidatesFilterIpIpv4Ipv6AndRejectsInvalid) {
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--filter-ip", "10.0.0.1"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        ASSERT_TRUE(res.capture.filter_ip.has_value());
        EXPECT_TRUE(res.capture.filter_ip->is_v4());
        EXPECT_EQ(res.capture.filter_ip_raw, "10.0.0.1");
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--filter-ip", "2001:db8::1"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        ASSERT_TRUE(res.capture.filter_ip.has_value());
        EXPECT_TRUE(res.capture.filter_ip->is_v6());
        EXPECT_EQ(res.capture.filter_ip_raw, "2001:db8::1");
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--filter-ip", "999.1.1.1"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(CliTest, ValidatesFilterPortBounds) {
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--filter-port", "443"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        ASSERT_TRUE(res.capture.filter_port.has_value());
        EXPECT_EQ(*res.capture.filter_port, static_cast<std::uint16_t>(443));
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--filter-port", "0"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--filter-port", "70000"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(CliTest, ValidatesCountDurationAndQueueSizeBounds) {
    for (const auto& args : std::vector<std::vector<std::string>>{
             {"capture", "-r", "a.pcap", "--count", "0"},
             {"capture", "-r", "a.pcap", "--duration", "0"},
             {"capture", "-r", "a.pcap", "--duration", "-1.5"},
             {"capture", "-r", "a.pcap", "--queue-size", "0"},
             {"capture", "-r", "a.pcap", "--queue-size", "2000000"}}) {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli(args, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(CliTest, ApiHostAndTokenRequireApiPort) {
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--api-host", "127.0.0.1"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "a.pcap", "--api-token", "secret"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::UsageError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(CliTest, FullValidLiveAndOfflineFlagCombinations) {
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture",
                              "-i", "eth0",
                              "--bpf", "tcp port 80",
                              "--filter-ip", "192.168.1.1",
                              "--filter-port", "80",
                              "--duration", "10.5",
                              "--count", "1000",
                              "--queue-size", "4096",
                              "--snaplen", "256",
                              "--no-promisc",
                              "--csv", "my_trace",
                              "--api-port", "8080",
                              "--api-host", "0.0.0.0",
                              "--api-token", "token123",
                              "-q"},
                             out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        EXPECT_EQ(res.command, CommandKind::Capture);
        EXPECT_EQ(res.capture.interface_arg, "eth0");
        EXPECT_FALSE(res.capture.read_file.has_value());
        EXPECT_EQ(res.capture.bpf_filter, "tcp port 80");
        ASSERT_TRUE(res.capture.filter_ip.has_value());
        EXPECT_EQ(res.capture.filter_ip_raw, "192.168.1.1");
        ASSERT_TRUE(res.capture.filter_port.has_value());
        EXPECT_EQ(*res.capture.filter_port, static_cast<std::uint16_t>(80));
        ASSERT_TRUE(res.capture.duration_seconds.has_value());
        EXPECT_DOUBLE_EQ(*res.capture.duration_seconds, 10.5);
        ASSERT_TRUE(res.capture.max_packets.has_value());
        EXPECT_EQ(*res.capture.max_packets, 1000ULL);
        EXPECT_EQ(res.capture.queue_size, static_cast<std::size_t>(4096));
        EXPECT_EQ(res.capture.snaplen, 256U);
        EXPECT_FALSE(res.capture.promiscuous);
        EXPECT_EQ(res.capture.csv_prefix, "my_trace");
        ASSERT_TRUE(res.capture.api_port.has_value());
        EXPECT_EQ(*res.capture.api_port, static_cast<std::uint16_t>(8080));
        EXPECT_EQ(res.capture.api_host, "0.0.0.0");
        EXPECT_EQ(res.capture.api_token, "token123");
        EXPECT_TRUE(res.capture.quiet);
    }
    {
        std::ostringstream out;
        std::ostringstream err;
        auto res = parse_cli({"capture", "-r", "test.pcap", "--csv", "offline_run"}, out, err);
        EXPECT_EQ(res.exit_code, ExitCode::Ok);
        EXPECT_EQ(res.command, CommandKind::Capture);
        EXPECT_EQ(res.capture.read_file, "test.pcap");
        EXPECT_FALSE(res.capture.interface_arg.has_value());
        EXPECT_EQ(res.capture.csv_prefix, "offline_run");
        EXPECT_TRUE(res.capture.promiscuous);
        EXPECT_EQ(res.capture.queue_size, static_cast<std::size_t>(8192));
        EXPECT_EQ(res.capture.snaplen, 65535U);
        EXPECT_EQ(res.capture.api_host, "127.0.0.1");
        EXPECT_FALSE(res.capture.quiet);
    }
}