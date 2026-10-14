#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>
#include <vector>

#include "netsight/core/Types.hpp"
#include "netsight/source/PcapFileReader.hpp"
#include "support/PcapWriter.hpp"
#include "support/TempFile.hpp"

using namespace netsight;
using namespace netsight::test;
using namespace std::chrono_literals;

namespace {

RawPacket make_packet(std::uint8_t id, std::int64_t us) {
    const std::vector<Byte> bytes = {id, 0xAA, 0xBB};
    return RawPacket(Timestamp{us}, bytes.data(), bytes.size(), static_cast<std::uint32_t>(bytes.size()));
}

struct ReadResult {
    std::vector<RawPacket> packets;
    StopReason reason;
    std::string error;
};

ReadResult read_all(PcapFileReader& reader) {
    ReadResult res;
    std::promise<StopReason> prom;
    auto fut = prom.get_future();

    reader.start(
        [&res](RawPacket pkt) {
            res.packets.push_back(std::move(pkt));
        },
        [&prom](StopReason r) {
            prom.set_value(r);
        });

    EXPECT_EQ(fut.wait_for(5s), std::future_status::ready);
    res.reason = fut.get();
    res.error = reader.last_error();
    return res;
}

void patch_file(const std::filesystem::path& path, std::size_t offset, const void* data, std::size_t size) {
    std::fstream fs(path, std::ios::in | std::ios::out | std::ios::binary);
    fs.seekp(offset);
    fs.write(reinterpret_cast<const char*>(data), size);
}

}

struct FormatParam {
    bool big_endian;
    bool nanoseconds;
};

class PcapRoundTripTest : public ::testing::TestWithParam<FormatParam> {};

TEST_P(PcapRoundTripTest, RoundTripAllFourVariants) {
    const auto& param = GetParam();
    TempFile tmp;

    const std::vector<RawPacket> input = {
        make_packet(1, 1'000'500),
        make_packet(2, 2'000'750),
        make_packet(3, 3'000'999)
    };

    PcapWriterOptions opts;
    opts.big_endian = param.big_endian;
    opts.nanoseconds = param.nanoseconds;

    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, input, opts));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr) << error;
    EXPECT_EQ(reader->link_type(), LinkType::Ethernet);

    auto result = read_all(*reader);
    EXPECT_EQ(result.reason, StopReason::EndOfStream);
    ASSERT_EQ(result.packets.size(), 3u);

    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(result.packets[i].timestamp.count(), input[i].timestamp.count());
        EXPECT_EQ(result.packets[i].data, input[i].data);
        EXPECT_EQ(result.packets[i].original_length, input[i].original_length);
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllFormats,
    PcapRoundTripTest,
    ::testing::Values(
        FormatParam{false, false}, 
        FormatParam{true, false},  
        FormatParam{false, true},  
        FormatParam{true, true}    
    )
);

TEST(PcapFileReaderTest, ExposesLinkTypeAndSnaplenBeforeStart) {
    TempFile tmp;
    PcapWriterOptions opts;
    opts.snaplen = 1500;
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Loop, {}, opts));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr) << error;

    EXPECT_EQ(reader->link_type(), LinkType::Loop);
    EXPECT_EQ(reader->snaplen(), 1500u);
}

TEST(PcapFileReaderTest, UnknownLinkTypeStillOpens) {
    TempFile tmp;
    PcapWriterOptions opts;
    opts.raw_linktype = 42;

    const std::vector<RawPacket> input = {make_packet(1, 1000)};
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, input, opts));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr) << error;
    EXPECT_EQ(reader->link_type(), LinkType::Unknown);

    auto result = read_all(*reader);
    EXPECT_EQ(result.reason, StopReason::EndOfStream);
    EXPECT_EQ(result.packets.size(), 1u);
}

TEST(PcapFileReaderTest, UpperBitsOfLinkTypeIgnored) {
    TempFile tmp;
    PcapWriterOptions opts;
    opts.raw_linktype = 0x10000001;
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, {}, opts));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr) << error;
    EXPECT_EQ(reader->link_type(), LinkType::Ethernet);
}

TEST(PcapFileReaderTest, EmptyCaptureEndsImmediately) {
    TempFile tmp;
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, {}));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr) << error;

    auto result = read_all(*reader);
    EXPECT_EQ(result.reason, StopReason::EndOfStream);
    EXPECT_TRUE(result.packets.empty());
}

TEST(PcapFileReaderTest, MissingFileFails) {
    std::string error;
    auto reader = PcapFileReader::open("non_existent_file_404.pcap", error);
    EXPECT_EQ(reader, nullptr);
    EXPECT_FALSE(error.empty());
    EXPECT_NE(error.find("non_existent_file_404.pcap"), std::string::npos);
}

TEST(PcapFileReaderTest, TooShortFileFails) {
    TempFile tmp;
    {
        std::ofstream out(tmp.path(), std::ios::binary);
        char buf[10] = {0};
        out.write(buf, sizeof(buf));
    }

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    EXPECT_EQ(reader, nullptr);
    EXPECT_NE(error.find("truncated"), std::string::npos);
}

TEST(PcapFileReaderTest, BadMagicFails) {
    TempFile tmp;
    {
        std::ofstream out(tmp.path(), std::ios::binary);
        char buf[24] = {0};
        out.write(buf, sizeof(buf));
    }

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    EXPECT_EQ(reader, nullptr);
    EXPECT_NE(error.find("bad magic"), std::string::npos);
}

TEST(PcapFileReaderTest, PcapngGivesHelpfulError) {
    TempFile tmp;
    {
        std::ofstream out(tmp.path(), std::ios::binary);
        const std::uint8_t pcapng_magic[4] = {0x0A, 0x0D, 0x0D, 0x0A};
        out.write(reinterpret_cast<const char*>(pcapng_magic), 4);
        char pad[20] = {0};
        out.write(pad, 20);
    }

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    EXPECT_EQ(reader, nullptr);
    EXPECT_NE(error.find("editcap"), std::string::npos);
}

TEST(PcapFileReaderTest, UnsupportedVersionFails) {
    TempFile tmp;
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, {}));

    std::uint16_t v3 = 3;
    patch_file(tmp.path(), 4, &v3, sizeof(v3));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    EXPECT_EQ(reader, nullptr);
    EXPECT_NE(error.find("unsupported pcap version"), std::string::npos);
}

TEST(PcapFileReaderTest, TruncatedLastRecordDeliversPriorPackets) {
    TempFile tmp;
    const std::vector<RawPacket> input = {
        make_packet(1, 1000),
        make_packet(2, 2000),
        make_packet(3, 3000)
    };
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, input));

    auto sz = std::filesystem::file_size(tmp.path());
    std::filesystem::resize_file(tmp.path(), sz - 5);

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr);

    auto result = read_all(*reader);
    ASSERT_EQ(result.packets.size(), 2u);
    EXPECT_EQ(result.reason, StopReason::Error);
    EXPECT_NE(result.error.find("truncated"), std::string::npos);
}

TEST(PcapFileReaderTest, OversizedRecordRejectedWithoutAllocating) {
    TempFile tmp;
    const std::vector<RawPacket> input = {make_packet(1, 1000)};
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, input));

    std::uint32_t bad_len = 0xFFFFFFFF;
    patch_file(tmp.path(), 32, &bad_len, sizeof(bad_len));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr);

    auto result = read_all(*reader);
    EXPECT_EQ(result.reason, StopReason::Error);
    EXPECT_NE(result.error.find("exceeds limit"), std::string::npos);
    EXPECT_TRUE(result.packets.empty());
}

TEST(PcapFileReaderTest, InclLenGreaterThanOrigLenRejected) {
    TempFile tmp;
    const std::vector<RawPacket> input = {make_packet(1, 1000)};
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, input));

    std::uint32_t incl = 10;
    std::uint32_t orig = 5;
    patch_file(tmp.path(), 32, &incl, sizeof(incl));
    patch_file(tmp.path(), 36, &orig, sizeof(orig));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr);

    auto result = read_all(*reader);
    EXPECT_EQ(result.reason, StopReason::Error);
    EXPECT_NE(result.error.find("incl_len > orig_len"), std::string::npos);
}

TEST(PcapFileReaderTest, InvalidMicrosecondFractionRejected) {
    TempFile tmp;
    const std::vector<RawPacket> input = {make_packet(1, 1000)};
    ASSERT_TRUE(write_pcap(tmp.path(), LinkType::Ethernet, input));

    std::uint32_t bad_frac = 1'000'000;
    patch_file(tmp.path(), 28, &bad_frac, sizeof(bad_frac));

    std::string error;
    auto reader = PcapFileReader::open(tmp.path(), error);
    ASSERT_NE(reader, nullptr);

    auto result = read_all(*reader);
    EXPECT_EQ(result.reason, StopReason::Error);
    EXPECT_NE(result.error.find("invalid timestamp fraction"), std::string::npos);
}