#pragma once
#include "netsight/core/IpAddress.hpp"
#include "netsight/parser/ParsedPacket.hpp"
#include <cstdint>
#include <optional>
namespace netsight {
struct PacketFilter {
    std::optional<IpAddress> ip;
    std::optional<std::uint16_t> port;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] bool matches(const ParsedPacket& packet) const noexcept;
};
}