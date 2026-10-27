#pragma once

#include "netsight/core/Types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>

namespace netsight {

struct IpAddress {
    NetworkProtocol protocol{NetworkProtocol::None};
    std::array<std::uint8_t, 16> bytes{0};

    constexpr IpAddress() noexcept = default;

    static IpAddress from_ipv4(const std::uint8_t* raw4) noexcept;
    static IpAddress from_ipv6(const std::uint8_t* raw16) noexcept;

    constexpr bool is_v4() const noexcept { return protocol == NetworkProtocol::IPv4; }
    constexpr bool is_v6() const noexcept { return protocol == NetworkProtocol::IPv6; }
    constexpr bool is_valid() const noexcept { return protocol != NetworkProtocol::None; }

    bool operator==(const IpAddress& other) const noexcept;
    bool operator!=(const IpAddress& other) const noexcept;
    bool operator<(const IpAddress& other) const noexcept;

    std::string to_string() const;
};

static_assert(std::is_trivially_copyable_v<IpAddress>,
              "IpAddress must be trivially copyable (zero heap allocations)");

}

namespace std {
template <>
struct hash<netsight::IpAddress> {
    std::size_t operator()(const netsight::IpAddress& ip) const noexcept {
        std::size_t h = 14695981039346656037ULL;
        h ^= static_cast<std::size_t>(ip.protocol);
        h *= 1099511628211ULL;
        for (std::uint8_t b : ip.bytes) {
            h ^= static_cast<std::size_t>(b);
            h *= 1099511628211ULL;
        }
        return h;
    }
};
}