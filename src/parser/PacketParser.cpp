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

constexpr TransportProtocol classify_ip_protocol(uint8_t proto) noexcept {
    switch (proto) {
        case 6:
            return TransportProtocol::TCP;
        case 17:
            return TransportProtocol::UDP;
        case 1:
            return TransportProtocol::ICMP;
        case 58:
            return TransportProtocol::ICMPv6;
        default:
            return TransportProtocol::Other;
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
        out_ether_type = 0x0800;
    } else if (af == 24 || af == 28 || af == 30) {
        out_ether_type = 0x86DD;
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

bool decode_ipv4(ByteReader& reader, ParsedPacket& out, uint8_t& out_proto, uint16_t& out_total_len) noexcept {
    if (reader.remaining() < 20) {
        out.status = ParseStatus::Truncated;
        return false;
    }

    const uint8_t ver_ihl = reader.u8();
    const uint8_t version = static_cast<uint8_t>(ver_ihl >> 4);
    const uint8_t ihl = static_cast<uint8_t>(ver_ihl & 0x0F);

    if (version != 4 || ihl < 5) {
        out.status = ParseStatus::Malformed;
        return false;
    }

    reader.skip(1);
    const uint16_t total_length = reader.u16_be();
    const uint16_t header_bytes = static_cast<uint16_t>(ihl * 4);

    if (total_length < header_bytes) {
        out.status = ParseStatus::Malformed;
        return false;
    }

    reader.skip(2);
    const uint16_t flags_frag = reader.u16_be();
    out.ip_ttl = reader.u8();
    const uint8_t protocol = reader.u8();
    reader.skip(2);

    const Byte* src_bytes = reader.bytes(4);
    const Byte* dst_bytes = reader.bytes(4);
    if (!src_bytes || !dst_bytes) {
        out.status = ParseStatus::Truncated;
        return false;
    }

    out.src_ip = IpAddress::from_ipv4(src_bytes);
    out.dst_ip = IpAddress::from_ipv4(dst_bytes);

    if (header_bytes > 20) {
        const std::size_t opt_len = header_bytes - 20;
        if (reader.remaining() < opt_len) {
            out.status = ParseStatus::Truncated;
            return false;
        }
        reader.skip(opt_len);
    }

    const bool mf = (flags_frag & 0x2000) != 0;
    const uint16_t frag_offset_units = static_cast<uint16_t>(flags_frag & 0x1FFF);
    out.fragment_offset = static_cast<uint16_t>(frag_offset_units * 8);
    out.is_fragment = mf || (frag_offset_units != 0);

    out.l4_offset = static_cast<uint32_t>(reader.position());
    out_proto = protocol;
    out_total_len = total_length;

    return true;
}

constexpr bool is_ipv6_extension_header(uint8_t nh) noexcept {
    return nh == 0  || 
           nh == 43 || 
           nh == 44 || 
           nh == 51 || 
           nh == 60;   
}

bool decode_ipv6(ByteReader& reader, ParsedPacket& out, uint8_t& out_l4_proto, uint16_t& out_payload_len) noexcept {
    if (reader.remaining() < 40) {
        out.status = ParseStatus::Truncated;
        return false;
    }

    const uint32_t vtc_flow = reader.u32_be();
    const uint8_t version = static_cast<uint8_t>(vtc_flow >> 28);

    if (version != 6) {
        out.status = ParseStatus::Malformed;
        return false;
    }

    const uint16_t payload_len = reader.u16_be();
    uint8_t current_nh = reader.u8();
    out.ip_ttl = reader.u8(); 

    const Byte* src_bytes = reader.bytes(16);
    const Byte* dst_bytes = reader.bytes(16);
    if (!src_bytes || !dst_bytes) {
        out.status = ParseStatus::Truncated;
        return false;
    }

    out.src_ip = IpAddress::from_ipv6(src_bytes);
    out.dst_ip = IpAddress::from_ipv6(dst_bytes);

    std::size_t ext_count = 0;
    constexpr std::size_t MAX_EXT_HEADERS = 8;

    while (is_ipv6_extension_header(current_nh)) {
        if (ext_count >= MAX_EXT_HEADERS) {
            out.status = ParseStatus::Malformed;
            return false;
        }

        if (current_nh == 44) {
            if (reader.remaining() < 8) {
                out.status = ParseStatus::Truncated;
                return false;
            }
            current_nh = reader.u8();
            reader.skip(1);
            const uint16_t frag_info = reader.u16_be();
            reader.skip(4);

            const uint16_t frag_offset_units = static_cast<uint16_t>(frag_info >> 3);
            const bool m_flag = (frag_info & 0x01) != 0;
            out.fragment_offset = static_cast<uint16_t>(frag_offset_units * 8);
            out.is_fragment = m_flag || (frag_offset_units != 0);
        } else if (current_nh == 51) {
            if (reader.remaining() < 4) {
                out.status = ParseStatus::Truncated;
                return false;
            }
            current_nh = reader.u8();
            const uint8_t ah_len = reader.u8();
            reader.skip(2);

            const std::size_t total_len = static_cast<std::size_t>(ah_len + 2) * 4;
            if (total_len < 4 || reader.remaining() < (total_len - 4)) {
                out.status = ParseStatus::Truncated;
                return false;
            }
            reader.skip(total_len - 4);
        } else {
            if (reader.remaining() < 2) {
                out.status = ParseStatus::Truncated;
                return false;
            }
            current_nh = reader.u8();
            const uint8_t ext_len_units = reader.u8();

            const std::size_t total_len = static_cast<std::size_t>(ext_len_units + 1) * 8;
            if (total_len < 2 || reader.remaining() < (total_len - 2)) {
                out.status = ParseStatus::Truncated;
                return false;
            }
            reader.skip(total_len - 2);
        }

        ext_count++;
    }

    out.l4_offset = static_cast<uint32_t>(reader.position());
    out_l4_proto = current_nh;
    out_payload_len = payload_len;
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

    if (out.network == NetworkProtocol::IPv4) {
        uint8_t l4_proto{0};
        uint16_t ip_total_len{0};
        if (!decode_ipv4(reader, out, l4_proto, ip_total_len)) {
            return out;
        }

        if (out.is_fragment && out.fragment_offset > 0) {
            out.transport = TransportProtocol::None;
            out.status = ParseStatus::Ok;
            return out;
        }

        out.transport = classify_ip_protocol(l4_proto);
        out.status = ParseStatus::Ok;
        return out;
    }

        if (out.network == NetworkProtocol::IPv4) {
        uint8_t l4_proto{0};
        uint16_t ip_total_len{0};
        if (!decode_ipv4(reader, out, l4_proto, ip_total_len)) {
            return out;
        }

        if (out.is_fragment && out.fragment_offset > 0) {
            out.transport = TransportProtocol::None;
            out.status = ParseStatus::Ok;
            return out;
        }

        out.transport = classify_ip_protocol(l4_proto);
        out.status = ParseStatus::Ok;
        return out;
    }

    if (out.network == NetworkProtocol::IPv6) {
        uint8_t l4_proto{0};
        uint16_t payload_len{0};
        if (!decode_ipv6(reader, out, l4_proto, payload_len)) {
            return out;
        }

        if (out.is_fragment && out.fragment_offset > 0) {
            out.transport = TransportProtocol::None;
            out.status = ParseStatus::Ok;
            return out;
        }

        out.transport = classify_ip_protocol(l4_proto);
        out.status = ParseStatus::Ok;
        return out;
    }

    out.status = ParseStatus::Ok;
    return out;
}

} 