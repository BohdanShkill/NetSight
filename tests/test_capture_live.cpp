#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <gtest/gtest.h>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "netsight/capture/Devices.hpp"
#include "netsight/capture/PcapLiveSource.hpp"
#include "netsight/capture/PcapRuntime.hpp"
#include "netsight/parser/PacketParser.hpp"

using namespace netsight;

namespace {

#define REQUIRE_OR_SKIP(reason)                                 \
    do {                                                        \
        const char* req = std::getenv("NETSIGHT_REQUIRE_LIVE"); \
        if (req != nullptr && std::string(req) == "1") {        \
            FAIL() << (reason);                                 \
        } else {                                                \
            GTEST_SKIP() << (reason);                           \
        }                                                       \
    } while (false)

#ifdef _WIN32
struct WinsockInit {
    WinsockInit() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WinsockInit() {
        WSACleanup();
    }
};
static WinsockInit g_winsock_init;
#endif

std::string find_loopback_interface() {
    std::string err;
    const auto ifaces = list_interfaces(err);
    for (const auto& iface : ifaces) {
        if (iface.is_loopback) {
            return iface.name;
        }
    }
    return "";
}

bool send_udp(std::uint16_t port, std::size_t payload_size, std::size_t count) {
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        return false;
    }
#else
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return false;
    }
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    std::vector<char> buffer(payload_size, 'A');
    bool ok = true;
    for (std::size_t i = 0; i < count; ++i) {
        auto sent = sendto(
            s,
            buffer.data(),
            static_cast<int>(buffer.size()),
            0,
            reinterpret_cast<const sockaddr*>(&addr),
            sizeof(addr));
        if (sent < 0) {
            ok = false;
            break;
        }
    }

#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return ok;
}

}

TEST(CaptureLiveTest, RuntimeLoadsOrReportsClearError) {
    std::string error;
    const bool loaded = ensure_pcap_loaded(error);
    if (loaded) {
        EXPECT_TRUE(error.empty());
    } else {
        EXPECT_NE(error.find("npcap.com"), std::string::npos)
            << "Error message must mention npcap.com, got: " << error;
    }
}

TEST(CaptureLiveTest, ListInterfacesNoError) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }
    std::string error;
    const auto ifaces = list_interfaces(error);
    EXPECT_TRUE(error.empty()) << "list_interfaces failed with error: " << error;
#ifndef _WIN32
    EXPECT_FALSE(ifaces.empty()) << "Expected at least loopback interface on Linux";
#endif
}

TEST(CaptureLiveTest, BpfValidExpressions) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    const std::vector<std::string> valid_filters = {
        "tcp port 80",
        "udp and port 53",
        "vlan and tcp"
    };

    for (const auto& filter : valid_filters) {
        std::string error;
        EXPECT_TRUE(validate_bpf(filter, LinkType::Ethernet, 65535, error))
            << "Filter should be valid: " << filter << ", error: " << error;
        EXPECT_TRUE(error.empty()) << "Error should be empty for: " << filter;
    }
}

TEST(CaptureLiveTest, BpfEmptyIsValid) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string error;
    EXPECT_TRUE(validate_bpf("", LinkType::Ethernet, 65535, error));
    EXPECT_TRUE(error.empty());
}

TEST(CaptureLiveTest, BpfInvalidSyntax) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    const std::vector<std::string> invalid_filters = {
        "tcp prt 80",
        "port",
        "udp and and"
    };

    for (const auto& filter : invalid_filters) {
        std::string error;
        EXPECT_FALSE(validate_bpf(filter, LinkType::Ethernet, 65535, error))
            << "Filter should be invalid: " << filter;
        EXPECT_FALSE(error.empty())
            << "Error message should not be empty for invalid filter: " << filter;
    }
}

TEST(CaptureLiveTest, BpfDependsOnLinkType) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    const std::string filter = "ether host 00:11:22:33:44:55";
    std::string error;

    EXPECT_TRUE(validate_bpf(filter, LinkType::Ethernet, 65535, error)) << error;
    EXPECT_TRUE(error.empty());

    error.clear();
    EXPECT_FALSE(validate_bpf(filter, LinkType::Null, 65535, error));
    EXPECT_FALSE(error.empty());
}

TEST(CaptureLiveTest, BpfUnknownLinkType) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string error;
    EXPECT_FALSE(validate_bpf("ip", LinkType::Unknown, 65535, error));
    EXPECT_FALSE(error.empty());
    EXPECT_NE(error.find("unknown link type"), std::string::npos);
}

TEST(CaptureLiveTest, OpenRejectsInvalidConfig) {
    std::string error;
    CaptureConfig cfg;

    EXPECT_EQ(PcapLiveSource::open("", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());
    EXPECT_NE(error.find("device"), std::string::npos);

    cfg.snapshot_length = 0;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());

    cfg.snapshot_length = 63;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());

    cfg.snapshot_length = 262145;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());
    cfg.snapshot_length = 65535;

    cfg.read_timeout_ms = 0;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());
    cfg.read_timeout_ms = 250;

    cfg.buffer_size_bytes = 0;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());

    cfg.buffer_size_bytes = 65535;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());

    cfg.buffer_size_bytes = 268435457;
    EXPECT_EQ(PcapLiveSource::open("any", cfg, error), nullptr);
    EXPECT_FALSE(error.empty());
}

TEST(CaptureLiveTest, OpenNonexistentDeviceFails) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string error;
    CaptureConfig cfg;
    auto source = PcapLiveSource::open("netsight-no-such-device-12345", cfg, error);

    EXPECT_EQ(source, nullptr);
    EXPECT_FALSE(error.empty());
}

TEST(CaptureLiveTest, OpenRejectsInvalidBpf) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "tcp prt 80";

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);

    if (!source && error.find("permission denied") != std::string::npos) {
        REQUIRE_OR_SKIP("insufficient permissions to open loopback: " + error);
        return;
    }

    EXPECT_EQ(source, nullptr);
    EXPECT_NE(error.find("invalid BPF"), std::string::npos)
        << "Expected 'invalid BPF' in error, got: " << error;
}

TEST(CaptureLiveTest, CapturesUdpOnLoopbackAndParses) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "udp and port 50505";
    cfg.read_timeout_ms = 250;

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);
    if (!source) {
        REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
        return;
    }

    LinkType lt = source->link_type();
    EXPECT_TRUE(lt == LinkType::Ethernet || lt == LinkType::Null || lt == LinkType::Loop || lt == LinkType::LinuxSll);

    std::mutex mtx;
    std::condition_variable cv;
    std::vector<RawPacket> packets;

    bool started = source->start(
        [&](RawPacket pkt) {
            std::lock_guard<std::mutex> lock(mtx);
            packets.push_back(std::move(pkt));
            cv.notify_one();
        },
        [](StopReason) {}
    );
    ASSERT_TRUE(started);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool found_target = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        while (std::chrono::steady_clock::now() < deadline) {
            send_udp(50505, 32, 2);
            if (cv.wait_for(lock, std::chrono::milliseconds(200), [&] {
                for (const auto& pkt : packets) {
                    auto parsed = parse_packet(pkt, lt);
                    if (parsed.status == ParseStatus::Ok &&
                        parsed.transport == TransportProtocol::UDP &&
                        parsed.dst_port == 50505) {
                        return true;
                    }
                }
                return false;
            })) {
                found_target = true;
                break;
            }
        }
    }

    EXPECT_TRUE(found_target);

    auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    for (const auto& pkt : packets) {
        auto parsed = parse_packet(pkt, lt);
        if (parsed.status == ParseStatus::Ok && parsed.dst_port == 50505) {
            EXPECT_EQ(parsed.transport, TransportProtocol::UDP);
            EXPECT_EQ(parsed.dst_ip.to_string(), "127.0.0.1");
            auto diff = std::abs(pkt.timestamp.count() - now_us);
            EXPECT_LT(diff, 60'000'000);
            break;
        }
    }

    source->stop();
}

TEST(CaptureLiveTest, SnaplenTruncatesCapture) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.snapshot_length = 64;
    cfg.bpf_filter = "udp and port 50506";
    cfg.read_timeout_ms = 250;

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);
    if (!source) {
        REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
        return;
    }

    std::mutex mtx;
    std::condition_variable cv;
    std::vector<RawPacket> packets;

    bool started = source->start(
        [&](RawPacket pkt) {
            std::lock_guard<std::mutex> lock(mtx);
            packets.push_back(std::move(pkt));
            cv.notify_one();
        },
        [](StopReason) {}
    );
    ASSERT_TRUE(started);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool found_target = false;
    {
        std::unique_lock<std::mutex> lock(mtx);
        while (std::chrono::steady_clock::now() < deadline) {
            send_udp(50506, 500, 2);
            if (cv.wait_for(lock, std::chrono::milliseconds(200), [&] {
                for (const auto& pkt : packets) {
                    if (pkt.original_length > 500) {
                        return true;
                    }
                }
                return false;
            })) {
                found_target = true;
                break;
            }
        }
    }

    EXPECT_TRUE(found_target);
    for (const auto& pkt : packets) {
        if (pkt.original_length > 500) {
            EXPECT_EQ(pkt.captured_length(), 64u);
            EXPECT_GT(pkt.original_length, 500u);
            break;
        }
    }

    source->stop();
}

TEST(CaptureLiveTest, StopReturnsWithinTimeout) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "udp and port 1";
    cfg.read_timeout_ms = 250;

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);
    if (!source) {
        REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
        return;
    }

    std::atomic<bool> complete_called{false};
    StopReason complete_reason{StopReason::Error};

    bool started = source->start(
        [](RawPacket) {},
        [&](StopReason r) {
            complete_reason = r;
            complete_called.store(true);
        }
    );
    ASSERT_TRUE(started);

    auto t0 = std::chrono::steady_clock::now();
    source->stop();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    EXPECT_LE(elapsed, cfg.read_timeout_ms + 1000);
    EXPECT_TRUE(complete_called.load());
    EXPECT_EQ(complete_reason, StopReason::StoppedByUser);
}

TEST(CaptureLiveTest, CallbackExceptionStopsWithError) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "udp and port 50507";
    cfg.read_timeout_ms = 250;

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);
    if (!source) {
        REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
        return;
    }

    std::atomic<bool> completed{false};
    StopReason reason{StopReason::StoppedByUser};
    std::mutex mtx;
    std::condition_variable cv;

    bool started = source->start(
        [](RawPacket) {
            throw std::runtime_error("boom");
        },
        [&](StopReason r) {
            std::lock_guard<std::mutex> lock(mtx);
            reason = r;
            completed.store(true);
            cv.notify_one();
        }
    );
    ASSERT_TRUE(started);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    {
        std::unique_lock<std::mutex> lock(mtx);
        while (!completed.load() && std::chrono::steady_clock::now() < deadline) {
            send_udp(50507, 32, 2);
            cv.wait_for(lock, std::chrono::milliseconds(200), [&] { return completed.load(); });
        }
    }

    EXPECT_TRUE(completed.load());
    EXPECT_EQ(reason, StopReason::Error);
    EXPECT_NE(source->last_error().find("boom"), std::string::npos);

    source->stop();
}

TEST(CaptureLiveTest, StatsAfterCapture) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "udp and port 50508";
    cfg.read_timeout_ms = 250;

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);
    if (!source) {
        REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
        return;
    }

    std::atomic<std::size_t> received_count{0};
    std::mutex mtx;
    std::condition_variable cv;

    bool started = source->start(
        [&](RawPacket) {
            received_count.fetch_add(1);
            cv.notify_one();
        },
        [](StopReason) {}
    );
    ASSERT_TRUE(started);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    {
        std::unique_lock<std::mutex> lock(mtx);
        while (received_count.load() == 0 && std::chrono::steady_clock::now() < deadline) {
            send_udp(50508, 32, 2);
            cv.wait_for(lock, std::chrono::milliseconds(200), [&] { return received_count.load() > 0; });
        }
    }

    source->stop();

    CaptureStats st = source->stats();
    EXPECT_GE(st.kernel_received, received_count.load());
    EXPECT_LT(st.kernel_dropped, (1ULL << 32));
}

TEST(CaptureLiveTest, DestructorStopsRunningCapture) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "udp and port 1";
    cfg.read_timeout_ms = 250;

    std::string error;
    {
        auto source = PcapLiveSource::open(loopback, cfg, error);
        if (!source) {
            REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
            return;
        }

        bool started = source->start([](RawPacket) {}, [](StopReason) {});
        ASSERT_TRUE(started);
    }
    EXPECT_TRUE(true);
}

TEST(CaptureLiveTest, StopBeforeStartDoesNotAbortCapture) {
    std::string runtime_err;
    if (!ensure_pcap_loaded(runtime_err)) {
        REQUIRE_OR_SKIP("libpcap/Npcap runtime unavailable: " + runtime_err);
        return;
    }

    std::string loopback = find_loopback_interface();
    if (loopback.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "udp and port 50509";
    cfg.read_timeout_ms = 250;

    std::string error;
    auto source = PcapLiveSource::open(loopback, cfg, error);
    if (!source) {
        REQUIRE_OR_SKIP("cannot open live capture on loopback: " + error);
        return;
    }

    source->stop();

    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> received{false};

    bool started = source->start(
        [&](RawPacket) {
            received.store(true);
            cv.notify_one();
        },
        [](StopReason) {}
    );
    ASSERT_TRUE(started);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    {
        std::unique_lock<std::mutex> lock(mtx);
        while (!received.load() && std::chrono::steady_clock::now() < deadline) {
            send_udp(50509, 32, 2);
            cv.wait_for(lock, std::chrono::milliseconds(200), [&] { return received.load(); });
        }
    }

    EXPECT_TRUE(received.load());
    source->stop();
}