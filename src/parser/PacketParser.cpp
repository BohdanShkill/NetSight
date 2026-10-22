#include "netsight/parser/PacketParser.hpp"
#include "netsight/core/ByteReader.hpp"

namespace netsight {

ParsedPacket parse_packet(const RawPacket& packet, LinkType link_type) noexcept {
    ParsedPacket out{};

    out.timestamp = packet.timestamp;
    out.wire_length = packet.original_length;
    out.captured_length = packet.captured_length();
    out.link_type = link_type;

    switch (link_type) {
        case LinkType::Ethernet:
        case LinkType::LinuxSll:
        case LinkType::Null:
        case LinkType::Loop:
            break;

        case LinkType::Unknown:
            out.status = ParseStatus::UnsupportedLinkType;
            return out;
    }

    if (link_type != LinkType::Ethernet &&
        link_type != LinkType::LinuxSll &&
        link_type != LinkType::Null &&
        link_type != LinkType::Loop) {
        out.status = ParseStatus::UnsupportedLinkType;
        return out;
    }

    return out;
}

}