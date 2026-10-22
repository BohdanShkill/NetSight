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

bool decode_null_or_loop(ByteReader& reader, uint16_t& out_ether_type, bool big_endian_only) noexcept {
    if (reader.remaining() < 4) {
        reader.skip(4);
        return false;
    }
    uint32_t af = 0;
    if (big_endian_only) {
        af = reader.u32_be();
    } else {
        const ByteReader peek = reader;
        const uint32_t af_le = reader.u32_le();
        if ((af_le >> 16) != 0) {
            ByteReader be_reader = peek;
            af = be_reader.u32_be();
        } else {
            af = af_le;
        }
    }
    if (!reader.ok()) {
        return false;
    }
    if (af == 2) {
        out_ether_type = 0x0800; // IPv4
    } else if (af == 24 || af == 28 || af == 30) {
        out_ether_type = 0x86DD; // IPv6
    } else {
        out_ether_type = 0;
    }
    return true;
}

bool decode_sll(ByteReader& reader, uint16_t& out_ether_type) noexcept {
    reader.skip(14);
    out_ether_type = reader.u16_be();
    return reader.ok();
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
        case LinkType::Null:
            ok = decode_null_or_loop(reader, ether_type, false);
            break;
        case LinkType::Loop:
            ok = decode_null_or_loop(reader, ether_type, true);
            break;
        case LinkType::LinuxSll:
            ok = decode_sll(reader, ether_type);
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

    if (link_type == LinkType::Ethernet || link_type == LinkType::LinuxSll) {
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