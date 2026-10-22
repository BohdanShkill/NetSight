#pragma once

#include <cstddef>
#include <cstdint>
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

    PacketBuilder& u16_be(uint16_t val) {
        buffer_.push_back(static_cast<Byte>((val >> 8) & 0xFF));
        buffer_.push_back(static_cast<Byte>(val & 0xFF));
        return *this;
    }

    PacketBuilder& bytes(std::size_t count, Byte fill = 0) {
        buffer_.insert(buffer_.end(), count, fill);
        return *this;
    }

    [[nodiscard]] RawPacket build(Timestamp ts = Timestamp{0}) const {
        return RawPacket(ts, buffer_.data(), buffer_.size(), static_cast<uint32_t>(buffer_.size()));
    }

    [[nodiscard]] const ByteBuffer& buffer() const noexcept {
        return buffer_;
    }

private:
    void append_bytes(const Byte* data, std::size_t len) {
        buffer_.insert(buffer_.end(), data, data + len);
    }

    ByteBuffer buffer_;
};

}