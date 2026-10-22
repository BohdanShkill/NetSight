#pragma once

#include "netsight/core/Types.hpp"
#include "netsight/parser/ParsedPacket.hpp"

namespace netsight {

[[nodiscard]] ParsedPacket parse_packet(const RawPacket& packet, LinkType link_type) noexcept;

}