#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <gtest/gtest.h>
#include <cstdlib>
#include <string>

#include "netsight/capture/PcapRuntime.hpp"
#include "netsight/capture/Devices.hpp"
#include "netsight/capture/PcapLiveSource.hpp"

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

    std::string if_err;
    const auto ifaces = list_interfaces(if_err);
    std::string loopback_name;
    for (const auto& iface : ifaces) {
        if (iface.is_loopback) {
            loopback_name = iface.name;
            break;
        }
    }

    if (loopback_name.empty()) {
        REQUIRE_OR_SKIP("no loopback interface found");
        return;
    }

    CaptureConfig cfg;
    cfg.bpf_filter = "tcp prt 80";

    std::string error;
    auto source = PcapLiveSource::open(loopback_name, cfg, error);

    if (!source && error.find("permission denied") != std::string::npos) {
        REQUIRE_OR_SKIP("insufficient permissions to open loopback: " + error);
        return;
    }

    EXPECT_EQ(source, nullptr);
    EXPECT_NE(error.find("invalid BPF"), std::string::npos)
        << "Expected 'invalid BPF' in error, got: " << error;
}