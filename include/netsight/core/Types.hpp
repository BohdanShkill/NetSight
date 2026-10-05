#pragma once

#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstddef>
#include <string>
#include <type_traits>

namespace netsight {

    using Byte = std::uint8_t;
    using ByteBuffer = std::vector<Byte>;
    using Timestamp = std::chrono::duration<std::int64_t, std::micro>;

    struct RawPacket {
        Timestamp timestamp;
        ByteBuffer data;
        std::uint32_t original_length;

        std::uint32_t captured_length() const noexcept {
                return static_cast<std::uint32_t>(data.size());
        }

        explicit RawPacket(Timestamp ts, const std::uint8_t* bytes, std::size_t cap_len, std::uint32_t orig_len):
        timestamp(ts),
        data(bytes != nullptr ? ByteBuffer(bytes, bytes + cap_len) : ByteBuffer()),
        original_length(orig_len)
        {}
    };

    static_assert(std::is_nothrow_move_constructible_v<RawPacket>);

    enum class ProtocolType {
        Unknown = 0,
        TCP,
        UDP,
        ICMP,
        ICMPv6,
        Other
    };

    enum class LinkType : std::uint16_t {
        Null = 0,
        Ethernet = 1,
        Loop = 108,
        LinuxSll = 113,
        Unknown = 65535
    };

    std::string to_string(ProtocolType proto);
    std::string to_string(LinkType link);


    inline std::uint16_t net_to_host_16(std::uint16_t val) noexcept {
    std::uint8_t b[2];
    std::memcpy(b, &val, sizeof(val));
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(b[0]) << 8) | b[1]);
    }

    inline std::uint16_t host_to_net_16(std::uint16_t val) noexcept {
    return net_to_host_16(val); 
    }
    
    inline std::uint32_t net_to_host_32(std::uint32_t val) noexcept {
    std::uint8_t b[4];
    std::memcpy(b, &val, sizeof(val));
    return (static_cast<std::uint32_t>(b[0]) << 24) |
           (static_cast<std::uint32_t>(b[1]) << 16) |
           (static_cast<std::uint32_t>(b[2]) << 8)  |
           static_cast<std::uint32_t>(b[3]);
    }

    inline std::uint32_t host_to_net_32(std::uint32_t val) noexcept {
    return net_to_host_32(val);
    }
}