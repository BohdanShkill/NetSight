#pragma once

#include <cstdint>
#include <vector>
#include <chrono>
#include <cstdlib>

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
        {}

        RawPacket(RawPacket&& other) = default;
        RawPacket& operator = (RawPacket&& other) = default; 
        RawPacket(const RawPacket& other) = default;
        RawPacket& operator = (const RawPacket& other) = default;
    };

    enum class ProtocolType{
        Unknown = 0,
        TCP,
        UDP,
        ICMP,
        ICMPv6,
        Other
    };

    inline std::uint16_t net_to_host_16(std::uint16_t value){
#if defined(_MSC_VER)
        return _byteswap_ushort(value);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(value);
#else   
        return value;
#endif
    }

    inline std::uint16_t host_to_net_16(std::uint16_t value){
#if defined(_MSC_VER)
        return _byteswap_ushort(value);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap16(value);
#else   
        return value;
#endif
    }

    inline std::uint32_t net_to_host_32(std::uint32_t value){
#if defined(_MSC_VER)
        return _byteswap_ulong(value);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(value);
#else   
        return value;
#endif
    }

    inline std::uint32_t host_to_net_32(std::uint32_t value){
#if defined(_MSC_VER)
        return _byteswap_ulong(value);
#elif defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(value);
#else   
        return value;
#endif
    }

    std::string protocol_to_string(ProtocolType protocol){
        switch (protocol)
        {
        case ProtocolType::TCP:
            return "TCP";
            break;
        case ProtocolType::UDP:
            return "UDP";
            break;
        case ProtocolType::ICMP:
            return "ICMP";
            break;
        case ProtocolType::ICMPv6:
            return "ICMPv6";
            break;
        default:
            return "Unknown";
        }
    }

}