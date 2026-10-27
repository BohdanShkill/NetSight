#pragma once

#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"

#include <array>
#include <cstdint>
#include <type_traits>

namespace netsight {

enum class ParseStatus {
    Ok,
    Truncated,
    UnsupportedLinkType,
    Malformed
};

enum class TransportProtocol : std::uint8_t {
    None = 0,
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    Other
};

struct TcpFlags {
    std::uint8_t value{0};

    constexpr bool fin() const noexcept { return (value & 0x01) != 0; }
    constexpr bool syn() const noexcept { return (value & 0x02) != 0; }
    constexpr bool rst() const noexcept { return (value & 0x04) != 0; }
    constexpr bool psh() const noexcept { return (value & 0x08) != 0; }
    constexpr bool ack() const noexcept { return (value & 0x10) != 0; }
    constexpr bool urg() const noexcept { return (value & 0x20) != 0; }
    constexpr bool ece() const noexcept { return (value & 0x40) != 0; }
    constexpr bool cwr() const noexcept { return (value & 0x80) != 0; }
};

static_assert(std::is_trivially_copyable_v<TcpFlags>);

struct ParsedPacket {
    Timestamp timestamp{};
    std::uint32_t wire_length{0};
    std::uint32_t captured_length{0};
    LinkType link_type{LinkType::Unknown};

    ParseStatus status{ParseStatus::Truncated};

    std::uint16_t ether_type{0};
    std::uint8_t vlan_count{0};
    std::array<std::uint16_t, 2> vlan_ids{0, 0};

    NetworkProtocol network{NetworkProtocol::None};
    std::uint32_t l3_offset{0};
    IpAddress src_ip{};
    IpAddress dst_ip{};
    std::uint8_t ip_ttl{0};
    bool is_fragment{false};
    std::uint16_t fragment_offset{0};

    TransportProtocol transport{TransportProtocol::None};
    std::uint32_t l4_offset{0};
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    TcpFlags tcp_flags{};
    std::uint8_t icmp_type{0};
    std::uint8_t icmp_code{0};

    std::uint32_t payload_offset{0};
    std::uint32_t payload_length{0};
};

static_assert(std::is_trivially_copyable_v<ParsedPacket>,
              "ParsedPacket must be trivially copyable (zero heap allocations)");

}