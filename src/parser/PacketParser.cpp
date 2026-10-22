#include "netsight/parser/PacketParser.hpp"
#include "netsight/core/ByteReader.hpp"

namespace {

using namespace netsight;

constexpr NetworkProtocol classify_ether_type(uint16_t ether_type) noexcept {
    switch (ether_type) {
        case 0x0800:
            return NetworkProtocol::IPv4;
        case 0x86DD:
            return NetworkProtocol::IPv6;
        case 0x0806:
            return NetworkProtocol::Arp;
        default:
            return NetworkProtocol::Other;
    }
}

bool decode_ethernet(ByteReader& reader, uint16_t& out_ether_type) noexcept {
    reader.skip(12);
    out_ether_type = reader.u16_be();
    return reader.ok();
}

bool peel_vlans(ByteReader& reader, uint16_t& ether_type, ParsedPacket& out) noexcept {
    while ((ether_type == 0x8100 || ether_type == 0x88A8 || ether_type == 0x9100) &&
           out.vlan_count < 2) {
        const uint16_t tci = reader.u16_be();
        const uint16_t inner = reader.u16_be();

        if (!reader.ok()) {
            return false;
        }

        out.vlan_ids[out.vlan_count] = static_cast<uint16_t>(tci & 0x0FFF);
        out.vlan_count++;
        ether_type = inner;
    }
    return true;
}

}

namespace netsight {

ParsedPacket parse_packet(const RawPacket& packet, LinkType link_type) noexcept {
    ParsedPacket out{};

    out.timestamp = packet.timestamp;
    out.wire_length = packet.original_length;
    out.captured_length = packet.captured_length();
    out.link_type = link_type;

    ByteReader reader(packet.data);
    uint16_t ether_type{0};
    bool ok{false};

    switch (link_type) {
        case LinkType::Ethernet:
            ok = decode_ethernet(reader, ether_type);
            break;

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

    if (!ok) {
        return out;
    }

    if (link_type == LinkType::Ethernet) {
        if (!peel_vlans(reader, ether_type, out)) {
            return out;
        }
    }

    out.ether_type = ether_type;
    out.network = classify_ether_type(ether_type);
    out.l3_offset = static_cast<uint32_t>(reader.position());
    out.status = ParseStatus::Ok;
    return out;
}

}