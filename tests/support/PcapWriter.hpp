#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

#include "netsight/core/Types.hpp"

namespace netsight::test {

struct PcapWriterOptions {
    bool big_endian{false};
    bool nanoseconds{false};
    std::uint32_t snaplen{65535};
    std::optional<std::uint32_t> raw_linktype{std::nullopt};
};

inline bool write_pcap(
    const std::filesystem::path& path,
    LinkType link_type,
    const std::vector<RawPacket>& packets,
    PcapWriterOptions options = {}) 
{
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }

    auto write_u16 = [&](std::uint16_t val) {
        std::uint8_t b[2];
        if (options.big_endian) {
            b[0] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
            b[1] = static_cast<std::uint8_t>(val & 0xFF);
        } else {
            b[0] = static_cast<std::uint8_t>(val & 0xFF);
            b[1] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
        }
        out.write(reinterpret_cast<const char*>(b), 2);
    };

    auto write_u32 = [&](std::uint32_t val) {
        std::uint8_t b[4];
        if (options.big_endian) {
            b[0] = static_cast<std::uint8_t>((val >> 24) & 0xFF);
            b[1] = static_cast<std::uint8_t>((val >> 16) & 0xFF);
            b[2] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
            b[3] = static_cast<std::uint8_t>(val & 0xFF);
        } else {
            b[0] = static_cast<std::uint8_t>(val & 0xFF);
            b[1] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
            b[2] = static_cast<std::uint8_t>((val >> 16) & 0xFF);
            b[3] = static_cast<std::uint8_t>((val >> 24) & 0xFF);
        }
        out.write(reinterpret_cast<const char*>(b), 4);
    };

    if (!options.big_endian && !options.nanoseconds) {
        const std::uint8_t magic[4] = {0xD4, 0xC3, 0xB2, 0xA1};
        out.write(reinterpret_cast<const char*>(magic), 4);
    } else if (options.big_endian && !options.nanoseconds) {
        const std::uint8_t magic[4] = {0xA1, 0xB2, 0xC3, 0xD4};
        out.write(reinterpret_cast<const char*>(magic), 4);
    } else if (!options.big_endian && options.nanoseconds) {
        const std::uint8_t magic[4] = {0x4D, 0x3C, 0xB2, 0xA1};
        out.write(reinterpret_cast<const char*>(magic), 4);
    } else {
        const std::uint8_t magic[4] = {0xA1, 0xB2, 0x3C, 0x4D};
        out.write(reinterpret_cast<const char*>(magic), 4);
    }

    write_u16(2); 
    write_u16(4); 
    write_u32(0); 
    write_u32(0); 
    write_u32(options.snaplen);
    
    std::uint32_t network = options.raw_linktype.value_or(static_cast<std::uint32_t>(link_type));
    write_u32(network);

    for (const auto& pkt : packets) {
        std::int64_t total_us = pkt.timestamp.count();
        std::uint32_t sec = static_cast<std::uint32_t>(total_us / 1'000'000);
        std::uint32_t frac = static_cast<std::uint32_t>(total_us % 1'000'000);

        if (options.nanoseconds) {
            frac *= 1000;
        }

        write_u32(sec);
        write_u32(frac);
        write_u32(pkt.captured_length());
        write_u32(pkt.original_length);

        if (!pkt.data.empty()) {
            out.write(reinterpret_cast<const char*>(pkt.data.data()), pkt.data.size());
        }
    }

    return out.good();
}

} 