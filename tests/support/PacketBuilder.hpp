#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "netsight/core/Types.hpp"

namespace netsight::test {

class PacketBuilder {
public:
    PacketBuilder() = default;

    PacketBuilder& ethernet(uint16_t ether_type) {
        const Byte default_mac_dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        const Byte default_mac_src[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};

        append_bytes(default_mac_dst, 6);
        append_bytes(default_mac_src, 6);
        u16_be(ether_type);
        return *this;
    }

    PacketBuilder& vlan(uint16_t vid, uint16_t inner_ether_type, uint8_t pcp = 0) {
        const uint16_t tci = static_cast<uint16_t>((static_cast<uint16_t>(pcp & 0x07) << 13) | (vid & 0x0FFF));
        u16_be(tci);
        u16_be(inner_ether_type);
        return *this;
    }

    PacketBuilder& null_header(uint32_t af, bool big_endian) {
        if (big_endian) {
            buffer_.push_back(static_cast<Byte>((af >> 24) & 0xFF));
            buffer_.push_back(static_cast<Byte>((af >> 16) & 0xFF));
            buffer_.push_back(static_cast<Byte>((af >> 8) & 0xFF));
            buffer_.push_back(static_cast<Byte>(af & 0xFF));
        } else {
            buffer_.push_back(static_cast<Byte>(af & 0xFF));
            buffer_.push_back(static_cast<Byte>((af >> 8) & 0xFF));
            buffer_.push_back(static_cast<Byte>((af >> 16) & 0xFF));
            buffer_.push_back(static_cast<Byte>((af >> 24) & 0xFF));
        }
        return *this;
    }

    PacketBuilder& sll(uint16_t protocol) {
        u16_be(0);
        u16_be(1);
        u16_be(6);
        bytes(8, 0);
        u16_be(protocol);
        return *this;
    }

    PacketBuilder& u8(uint8_t val) {
        buffer_.push_back(static_cast<Byte>(val));
        return *this;
    }

    PacketBuilder& u16_be(uint16_t val) {
        buffer_.push_back(static_cast<Byte>((val >> 8) & 0xFF));
        buffer_.push_back(static_cast<Byte>(val & 0xFF));
        return *this;
    }

    PacketBuilder& u32_be(uint32_t val) {
        buffer_.push_back(static_cast<Byte>((val >> 24) & 0xFF));
        buffer_.push_back(static_cast<Byte>((val >> 16) & 0xFF));
        buffer_.push_back(static_cast<Byte>((val >> 8) & 0xFF));
        buffer_.push_back(static_cast<Byte>(val & 0xFF));
        return *this;
    }

    PacketBuilder& bytes(std::size_t count, Byte fill = 0) {
        buffer_.insert(buffer_.end(), count, fill);
        return *this;
    }

    PacketBuilder& ipv4(std::array<uint8_t, 4> src_ip = {192, 168, 1, 1},
                        std::array<uint8_t, 4> dst_ip = {192, 168, 1, 2},
                        uint8_t protocol = 6,
                        uint8_t ttl = 64,
                        uint16_t total_length = 0,
                        uint8_t ihl = 5,
                        uint16_t flags_and_offset = 0,
                        uint8_t version = 4) {
        ipv4_start_ = buffer_.size();
        ipv4_len_offset_ = buffer_.size() + 2;
        auto_calc_ipv4_ = (total_length == 0);

        u8(static_cast<uint8_t>((static_cast<uint8_t>(version & 0x0F) << 4) | (ihl & 0x0F)));
        u8(0);
        u16_be(total_length);
        u16_be(0x1234);
        u16_be(flags_and_offset);
        u8(ttl);
        u8(protocol);
        u16_be(0);
        append_bytes(src_ip.data(), 4);
        append_bytes(dst_ip.data(), 4);

        if (ihl > 5) {
            bytes(static_cast<std::size_t>(ihl - 5) * 4, 0);
        }
        return *this;
    }

    PacketBuilder& ipv4_options(const std::vector<Byte>& opts) {
        append_bytes(opts.data(), opts.size());
        return *this;
    }

    PacketBuilder& ipv6(std::array<uint8_t, 16> src_ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                        std::array<uint8_t, 16> dst_ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
                        uint8_t next_header = 6,
                        uint8_t hop_limit = 64,
                        uint16_t payload_length = 0,
                        uint8_t version = 6) {
        ipv6_start_ = buffer_.size();
        ipv6_len_offset_ = buffer_.size() + 4;
        auto_calc_ipv6_ = (payload_length == 0);

        const uint32_t vtc_flow = static_cast<uint32_t>(version & 0x0F) << 28;
        u32_be(vtc_flow);
        u16_be(payload_length);
        u8(next_header);
        u8(hop_limit);
        append_bytes(src_ip.data(), 16);
        append_bytes(dst_ip.data(), 16);
        return *this;
    }

    PacketBuilder& ipv6_ext_header(uint8_t next_header, uint8_t length_units, const std::vector<Byte>& data) {
        u8(next_header);
        u8(length_units);
        append_bytes(data.data(), data.size());
        return *this;
    }

    PacketBuilder& ipv6_fragment(uint8_t next_header,
                                  uint16_t fragment_offset,
                                  bool m_flag,
                                  uint32_t identification = 0x12345678) {
        u8(next_header);
        u8(0);
        const uint16_t frag_info = static_cast<uint16_t>(((fragment_offset / 8) << 3) | (m_flag ? 1 : 0));
        u16_be(frag_info);
        u32_be(identification);
        return *this;
    }

    PacketBuilder& tcp(uint16_t src_port = 12345,
                       uint16_t dst_port = 80,
                       uint8_t flags = 0x02,
                       uint32_t seq = 1000,
                       uint32_t ack = 0,
                       uint8_t data_offset = 5,
                       uint16_t window = 65535) {
        u16_be(src_port);
        u16_be(dst_port);
        u32_be(seq);
        u32_be(ack);
        u8(static_cast<uint8_t>((data_offset & 0x0F) << 4));
        u8(flags);
        u16_be(window);
        u16_be(0);
        u16_be(0);

        if (data_offset > 5) {
            bytes(static_cast<std::size_t>(data_offset - 5) * 4, 0);
        }
        return *this;
    }

    PacketBuilder& tcp_options(const std::vector<Byte>& opts) {
        append_bytes(opts.data(), opts.size());
        return *this;
    }

    PacketBuilder& udp(uint16_t src_port, uint16_t dst_port, uint16_t length = 0) {
        udp_start_ = buffer_.size();
        udp_len_offset_ = buffer_.size() + 4;
        auto_calc_udp_ = (length == 0);

        u16_be(src_port);
        u16_be(dst_port);
        u16_be(length);
        u16_be(0);
        return *this;
    }

    PacketBuilder& icmp(uint8_t type, uint8_t code) {
        u8(type);
        u8(code);
        u16_be(0);
        u32_be(0);
        return *this;
    }

    PacketBuilder& icmpv6(uint8_t type, uint8_t code) {
        u8(type);
        u8(code);
        u16_be(0);
        return *this;
    }

    PacketBuilder& payload(std::string_view str) {
        append_bytes(reinterpret_cast<const Byte*>(str.data()), str.size());
        return *this;
    }

    PacketBuilder& payload(const std::vector<Byte>& data) {
        append_bytes(data.data(), data.size());
        return *this;
    }

    [[nodiscard]] RawPacket build(Timestamp ts = Timestamp{0}) const {
        ByteBuffer buf = buffer_;

        if (auto_calc_ipv4_ && ipv4_len_offset_ + 1 < buf.size()) {
            const auto len = static_cast<uint16_t>(buf.size() - ipv4_start_);
            buf[ipv4_len_offset_] = static_cast<Byte>((len >> 8) & 0xFF);
            buf[ipv4_len_offset_ + 1] = static_cast<Byte>(len & 0xFF);
        }

        if (auto_calc_ipv6_ && ipv6_len_offset_ + 1 < buf.size()) {
            const auto len = static_cast<uint16_t>(buf.size() - (ipv6_start_ + 40));
            buf[ipv6_len_offset_] = static_cast<Byte>((len >> 8) & 0xFF);
            buf[ipv6_len_offset_ + 1] = static_cast<Byte>(len & 0xFF);
        }

        if (auto_calc_udp_ && udp_len_offset_ + 1 < buf.size()) {
            const auto len = static_cast<uint16_t>(buf.size() - udp_start_);
            buf[udp_len_offset_] = static_cast<Byte>((len >> 8) & 0xFF);
            buf[udp_len_offset_ + 1] = static_cast<Byte>(len & 0xFF);
        }

        return RawPacket(ts, buf.data(), buf.size(), static_cast<uint32_t>(buf.size()));
    }

    [[nodiscard]] const ByteBuffer& buffer() const noexcept {
        return buffer_;
    }

private:
    void append_bytes(const Byte* data, std::size_t len) {
        buffer_.insert(buffer_.end(), data, data + len);
    }

    ByteBuffer buffer_;

    std::size_t ipv4_start_{0};
    std::size_t ipv4_len_offset_{0};
    bool auto_calc_ipv4_{false};

    std::size_t ipv6_start_{0};
    std::size_t ipv6_len_offset_{0};
    bool auto_calc_ipv6_{false};

    std::size_t udp_start_{0};
    std::size_t udp_len_offset_{0};
    bool auto_calc_udp_{false};
};

}