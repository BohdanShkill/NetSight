#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <gtest/gtest.h>
#include <cstdlib>
#include <string>

#include "netsight/capture/PcapRuntime.hpp"
#include "netsight/capture/Devices.hpp"

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