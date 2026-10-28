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