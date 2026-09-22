#pragma once

#include <cstdint>
#include <vector>
#include <chrono>

namespace netsight {
    using Byte = std::uint8_t;
    using ByteBuffer = std::vector<Byte>;
    using Timestamp = std::chrono::steady_clock::time_point;

    struct RawPacket
    {
        Timestamp timestamp;
        ByteBuffer data;
        std::uint32_t captured_length;
        std::uint32_t original_length;

        RawPacket(const Byte* raw_data, std::uint32_t cap_len, std::uint32_t orig_len)
        : data(raw_data, raw_data + cap_len),
          captured_length(cap_len),
          original_length(orig_len)
        
        {
        }
        RawPacket(RawPacket&& other) = default;
        RawPacket& operator = (RawPacket&& other) = default; 
        RawPacket(const RawPacket& other) = default;
        RawPacket& operator = (const RawPacket& other) = default;
    };
    
}