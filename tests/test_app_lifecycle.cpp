#include <gtest/gtest.h>

#include "App.hpp"

#include "support/FakePacketSource.hpp"
#include "support/PacketBuilder.hpp"
#include "support/PcapWriter.hpp"
#include "support/TempFile.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#ifndef NETSIGHT_TEST_DATA_DIR
#define NETSIGHT_TEST_DATA_DIR "tests/data"
#endif

#ifndef NETSIGHT_EXE_PATH
#define NETSIGHT_EXE_PATH "netsight"
#endif

using namespace netsight;
using namespace netsight::test;

namespace {

std::string read_binary_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

struct CsvCleanupGuard {
    std::string prefix;
    ~CsvCleanupGuard() {
        std::error_code ec;
        std::filesystem::remove(prefix + "_timeseries.csv", ec);
        std::filesystem::remove(prefix + "_summary.csv", ec);
    }
};

}

TEST(AppLifecycleTest, ListFormatsInterfacesAndHandlesEmptyAndError) {
    {
        std::istringstream in;
        std::ostringstream out;
        std::ostringstream err;
        AppEnv env{in, out, err};
        env.list_interfaces_fn = [](std::string&) -> std::vector<NetworkInterface> {
            return {
                {"eth0", "Primary adapter", "192.168.1.10", false, true},
                {"lo", "Loopback", "127.0.0.1", true, false}};
        };

        EXPECT_EQ(run_netsight({"list"}, env), ExitCode::Ok);
        EXPECT_TRUE(err.str().empty());
        EXPECT_NE(out.str().find("eth0"), std::string::npos);
        EXPECT_NE(out.str().find("192.168.1.10"), std::string::npos);
        EXPECT_NE(out.str().find("[up]"), std::string::npos);
        EXPECT_NE(out.str().find("[loopback]"), std::string::npos);
        EXPECT_NE(out.str().find("[down]"), std::string::npos);
    }

    {
        std::istringstream in;
        std::ostringstream out;
        std::ostringstream err;
        AppEnv env{in, out, err};
        env.list_interfaces_fn = [](std::string&) -> std::vector<NetworkInterface> {
            return {};
        };

        EXPECT_EQ(run_netsight({"list"}, env), ExitCode::Ok);
        EXPECT_TRUE(err.str().empty());
        EXPECT_NE(out.str().find("No network interfaces"), std::string::npos);
    }

    {
        std::istringstream in;
        std::ostringstream out;
        std::ostringstream err;
        AppEnv env{in, out, err};
        env.list_interfaces_fn = [](std::string& err_out) -> std::vector<NetworkInterface> {
            err_out = "Npcap driver unavailable";
            return {};
        };

        EXPECT_EQ(run_netsight({"list"}, env), ExitCode::RuntimeError);
        EXPECT_NE(err.str().find("Npcap driver unavailable"), std::string::npos);
    }
}

TEST(AppLifecycleTest, CaptureWithoutSourceInNonTtyFailsFast) {
    std::istringstream in("0\n");
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};
    env.stdin_is_tty = false;
    env.stdout_is_tty = false;

    EXPECT_EQ(run_netsight({"capture"}, env), ExitCode::UsageError);
    EXPECT_FALSE(err.str().empty());
}

TEST(AppLifecycleTest, InteractiveTtyInvalidSelectionReturnsUsageError) {
    for (const std::string& bad_input : {"99\n", "abc\n"}) {
        std::istringstream in(bad_input);
        std::ostringstream out;
        std::ostringstream err;
        AppEnv env{in, out, err};
        env.stdin_is_tty = true;
        env.stdout_is_tty = true;
        env.list_interfaces_fn = [](std::string&) -> std::vector<NetworkInterface> {
            return {{"eth0", "Primary", "10.0.0.1", false, true}};
        };

        EXPECT_EQ(run_netsight({"capture"}, env), ExitCode::UsageError);
        EXPECT_NE(out.str().find("eth0"), std::string::npos);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(AppLifecycleTest, MissingOrCorruptPcapReturnsRuntimeError) {
    {
        TempFile csv_base("netsight_no_pcap_", "");
        CsvCleanupGuard cleanup{csv_base.string()};

        std::istringstream in;
        std::ostringstream out;
        std::ostringstream err;
        AppEnv env{in, out, err};

        const auto rc = run_netsight(
            {"capture", "-r", "/nonexistent_dir_xyz/no_such_file.pcap", "--csv", csv_base.string()},
            env);
        EXPECT_EQ(rc, ExitCode::RuntimeError);
        EXPECT_FALSE(err.str().empty());
        EXPECT_FALSE(std::filesystem::exists(csv_base.string() + "_timeseries.csv"));
        EXPECT_FALSE(std::filesystem::exists(csv_base.string() + "_summary.csv"));
    }

    {
        TempFile corrupt_pcap("netsight_corrupt_", ".pcap");
        {
            std::ofstream ofs(corrupt_pcap.path(), std::ios::binary);
            const std::uint8_t valid_hdr_plus_truncated_pkt[] = {
                0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
                0x00, 0x11, 0x22, 0x33};
            ofs.write(reinterpret_cast<const char*>(valid_hdr_plus_truncated_pkt),
                      sizeof(valid_hdr_plus_truncated_pkt));
        }

        std::istringstream in;
        std::ostringstream out;
        std::ostringstream err;
        AppEnv env{in, out, err};

        EXPECT_EQ(run_netsight({"capture", "-r", corrupt_pcap.string()}, env), ExitCode::RuntimeError);
        EXPECT_FALSE(err.str().empty());
    }
}

TEST(AppLifecycleTest, BadCsvPathFailsBeforeCapture) {
    const std::string valid_pcap = std::string(NETSIGHT_TEST_DATA_DIR) + "/lo_tcp.pcap";

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};

    const auto rc = run_netsight(
        {"capture", "-r", valid_pcap, "--csv", "/nonexistent_dir_xyz_98765/out/report"},
        env);
    EXPECT_EQ(rc, ExitCode::RuntimeError);
    EXPECT_FALSE(err.str().empty());
}

TEST(AppLifecycleTest, OfflineReplayWritesBinaryCrlfCsvAndSummary) {
    TempFile pcap_file("netsight_replay_", ".pcap");
    TempFile csv_base("netsight_replay_csv_", "");
    CsvCleanupGuard cleanup{csv_base.string()};

    std::vector<RawPacket> pkts;
    pkts.reserve(30);
    for (std::size_t i = 0; i < 30; ++i) {
        const std::int64_t ts_us = 1'000'000LL + static_cast<std::int64_t>(i) * 100'000LL;
        pkts.push_back(PacketBuilder{}
                           .ethernet(0x0800)
                           .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6)
                           .tcp(static_cast<std::uint16_t>(10000 + i), 80, 0x02)
                           .build(Timestamp{ts_us}));
    }
    ASSERT_TRUE(write_pcap(pcap_file.path(), LinkType::Ethernet, pkts));

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};

    const auto rc = run_netsight({"capture", "-r", pcap_file.string(), "--csv", csv_base.string()}, env);
    EXPECT_EQ(rc, ExitCode::Ok);
    EXPECT_TRUE(err.str().empty());
    EXPECT_FALSE(out.str().empty());

    const std::string ts_content = read_binary_file(csv_base.string() + "_timeseries.csv");
    const std::string sum_content = read_binary_file(csv_base.string() + "_summary.csv");

    ASSERT_FALSE(ts_content.empty());
    ASSERT_FALSE(sum_content.empty());
    EXPECT_EQ(ts_content.find("\r\r\n"), std::string::npos);
    EXPECT_EQ(sum_content.find("\r\r\n"), std::string::npos);
    EXPECT_NE(ts_content.find("\r\n"), std::string::npos);
    EXPECT_NE(sum_content.find("totals,,packets,30\r\n"), std::string::npos);
    EXPECT_NE(sum_content.find("meta,,stop_reason,eof\r\n"), std::string::npos);
}

TEST(AppLifecycleTest, CountOptionStopsAtExactPacketCount) {
    TempFile pcap_file("netsight_count_", ".pcap");
    TempFile csv_base("netsight_count_csv_", "");
    CsvCleanupGuard cleanup{csv_base.string()};

    std::vector<RawPacket> pkts;
    pkts.reserve(200);
    for (std::size_t i = 0; i < 200; ++i) {
        const std::int64_t ts_us = 1'000'000LL + static_cast<std::int64_t>(i) * 10'000LL;
        pkts.push_back(PacketBuilder{}
                           .ethernet(0x0800)
                           .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 17)
                           .udp(12345, 53)
                           .build(Timestamp{ts_us}));
    }
    ASSERT_TRUE(write_pcap(pcap_file.path(), LinkType::Ethernet, pkts));

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};

    const auto rc = run_netsight(
        {"capture", "-r", pcap_file.string(), "--count", "15", "--csv", csv_base.string()},
        env);
    EXPECT_EQ(rc, ExitCode::Ok);
    EXPECT_TRUE(err.str().empty());

    const std::string sum_content = read_binary_file(csv_base.string() + "_summary.csv");
    EXPECT_NE(sum_content.find("totals,,packets,15\r\n"), std::string::npos);
    EXPECT_NE(sum_content.find("meta,,stop_reason,count\r\n"), std::string::npos);
}

TEST(AppLifecycleTest, FilterIpAndPortAppliedEndToEnd) {
    TempFile pcap_file("netsight_filter_", ".pcap");
    TempFile csv_base("netsight_filter_csv_", "");
    CsvCleanupGuard cleanup{csv_base.string()};

    std::vector<RawPacket> pkts;
    for (int i = 0; i < 10; ++i) {
        pkts.push_back(PacketBuilder{}
                           .ethernet(0x0800)
                           .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6)
                           .tcp(50000, 443, 0x10)
                           .build(Timestamp{1'000'000LL + i * 1000LL}));
    }
    for (int i = 0; i < 6; ++i) {
        pkts.push_back(PacketBuilder{}
                           .ethernet(0x0800)
                           .ipv4({10, 0, 0, 3}, {10, 0, 0, 4}, 17)
                           .udp(50000, 53)
                           .build(Timestamp{1'020'000LL + i * 1000LL}));
    }
    ASSERT_TRUE(write_pcap(pcap_file.path(), LinkType::Ethernet, pkts));

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};

    const auto rc = run_netsight(
        {"capture", "-r", pcap_file.string(),
         "--filter-ip", "10.0.0.1",
         "--filter-port", "443",
         "--csv", csv_base.string()},
        env);
    EXPECT_EQ(rc, ExitCode::Ok);
    EXPECT_TRUE(err.str().empty());

    const std::string sum_content = read_binary_file(csv_base.string() + "_summary.csv");
    EXPECT_NE(sum_content.find("totals,,packets,10\r\n"), std::string::npos);
    EXPECT_NE(sum_content.find("drops,,filtered_out,6\r\n"), std::string::npos);
}

TEST(AppLifecycleTest, QuietFlagSuppressesStdoutButKeepsCsv) {
    const std::string valid_pcap = std::string(NETSIGHT_TEST_DATA_DIR) + "/lo_tcp.pcap";
    TempFile csv_base("netsight_quiet_csv_", "");
    CsvCleanupGuard cleanup{csv_base.string()};

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};

    const auto rc = run_netsight(
        {"capture", "-r", valid_pcap, "--csv", csv_base.string(), "--quiet"},
        env);
    EXPECT_EQ(rc, ExitCode::Ok);
    EXPECT_TRUE(out.str().empty());
    EXPECT_TRUE(err.str().empty());
    EXPECT_FALSE(read_binary_file(csv_base.string() + "_timeseries.csv").empty());
    EXPECT_FALSE(read_binary_file(csv_base.string() + "_summary.csv").empty());
}

TEST(AppLifecycleTest, NonLoopbackApiWithoutTokenPrintsSecurityWarning) {
    const std::string valid_pcap = std::string(NETSIGHT_TEST_DATA_DIR) + "/lo_tcp.pcap";

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};

    const auto rc = run_netsight(
        {"capture", "-r", valid_pcap, "--api-port", "0", "--api-host", "0.0.0.0", "--quiet"},
        env);
    EXPECT_EQ(rc, ExitCode::Ok);
    EXPECT_NE(err.str().find("WARNING"), std::string::npos);
}

TEST(AppLifecycleTest, RestApiServesLiveSnapshotsUntilGracefulStop) {
    TempFile csv_base("netsight_rest_e2e_", "");
    CsvCleanupGuard cleanup{csv_base.string()};

    std::atomic<bool> stop_flag{false};
    std::promise<std::uint16_t> port_promise;
    auto port_future = port_promise.get_future();

    std::istringstream in;
    std::ostringstream out;
    std::ostringstream err;
    AppEnv env{in, out, err};
    env.stop_requested_fn = [&stop_flag]() {
        return stop_flag.load(std::memory_order_relaxed);
    };
    env.on_api_listening = [&port_promise](std::uint16_t port) {
        port_promise.set_value(port);
    };
    env.open_live_source_fn = [](const std::string&, const CaptureConfig&, std::string&)
        -> std::unique_ptr<IPacketSource> {
        std::vector<RawPacket> pkts;
        for (int i = 0; i < 5; ++i) {
            pkts.push_back(PacketBuilder{}
                               .ethernet(0x0800)
                               .ipv4({10, 0, 0, 1}, {10, 0, 0, 2}, 6)
                               .tcp(12345, 80, 0x10)
                               .build(Timestamp{1'000'000LL + i * 10'000LL}));
        }
        return std::make_unique<FakePacketSource>(std::move(pkts), LinkType::Ethernet, std::nullopt, true);
    };

    std::thread app_thread([&]() {
        const auto rc = run_netsight(
            {"capture", "-i", "fake0", "--api-port", "0", "--csv", csv_base.string(), "--quiet"},
            env);
        EXPECT_EQ(rc, ExitCode::Ok);
    });

    ASSERT_EQ(port_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const std::uint16_t port = port_future.get();
    ASSERT_GT(port, 0);

    httplib::Client client("127.0.0.1", port);
    client.set_connection_timeout(std::chrono::seconds(2));
    client.set_read_timeout(std::chrono::seconds(2));

    auto health_res = client.Get("/api/v1/health");
    ASSERT_TRUE(health_res);
    EXPECT_EQ(health_res->status, 200);
    const auto health_json = nlohmann::json::parse(health_res->body);
    EXPECT_EQ(health_json.at("status"), "ok");

    auto stats_res = client.Get("/api/v1/stats");
    ASSERT_TRUE(stats_res);
    EXPECT_EQ(stats_res->status, 200);
    const auto stats_json = nlohmann::json::parse(stats_res->body);
    ASSERT_TRUE(stats_json.contains("totals"));
    EXPECT_TRUE(stats_json.at("totals").contains("packets"));

    stop_flag.store(true, std::memory_order_relaxed);
    app_thread.join();

    const std::string sum_content = read_binary_file(csv_base.string() + "_summary.csv");
    EXPECT_NE(sum_content.find("totals,,packets,5\r\n"), std::string::npos);
    EXPECT_NE(sum_content.find("meta,,stop_reason,signal\r\n"), std::string::npos);

    auto after_stop = client.Get("/api/v1/health");
    EXPECT_FALSE(after_stop);
}

TEST(AppLifecycleTest, ExecutableBinarySmokeTest) {
    const std::filesystem::path exe_path(NETSIGHT_EXE_PATH);
    ASSERT_TRUE(std::filesystem::exists(exe_path));

    const std::filesystem::path pcap_path = std::filesystem::path(NETSIGHT_TEST_DATA_DIR) / "lo_tcp.pcap";
    ASSERT_TRUE(std::filesystem::exists(pcap_path));

#ifdef _WIN32
    const std::string cmd_ver = "\"\"" + exe_path.string() + "\" --version > nul\"";
    const std::string cmd_cap = "\"\"" + exe_path.string() + "\" capture -r \"" + pcap_path.string() + "\" --quiet\"";
#else
    const std::string cmd_ver = "\"" + exe_path.string() + "\" --version > /dev/null";
    const std::string cmd_cap = "\"" + exe_path.string() + "\" capture -r \"" + pcap_path.string() + "\" --quiet";
#endif

    EXPECT_EQ(std::system(cmd_ver.c_str()), 0);
    EXPECT_EQ(std::system(cmd_cap.c_str()), 0);
}