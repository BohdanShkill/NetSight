#include "netsight/source/PcapFileReader.hpp"
#include "netsight/core/ByteReader.hpp"

#include <cstdint>
#include <fstream>
#include <utility>

namespace netsight {

namespace {

LinkType to_link_type(std::uint32_t val) {
    switch (val) {
        case 0:   return LinkType::Null;
        case 1:   return LinkType::Ethernet;
        case 108: return LinkType::Loop;
        case 113: return LinkType::LinuxSll;
        default:  return LinkType::Unknown;
    }
}

}

PcapFileReader::PcapFileReader(
    std::ifstream stream,
    bool big_endian,
    bool nanoseconds,
    std::uint32_t snaplen,
    LinkType link_type,
    std::filesystem::path path)
    : stream_(std::move(stream)),
      big_endian_(big_endian),
      nanoseconds_(nanoseconds),
      snaplen_(snaplen),
      link_type_(link_type),
      path_(std::move(path)) {}

std::uint16_t PcapFileReader::read_u16(ByteReader& r) const noexcept {
    return big_endian_ ? r.u16_be() : r.u16_le();
}

std::uint32_t PcapFileReader::read_u32(ByteReader& r) const noexcept {
    return big_endian_ ? r.u32_be() : r.u32_le();
}

std::unique_ptr<PcapFileReader> PcapFileReader::open(
    const std::filesystem::path& path,
    std::string& error) 
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        error = "cannot open file: " + path.string();
        return nullptr;
    }

    Byte header[24];
    stream.read(reinterpret_cast<char*>(header), sizeof(header));
    if (stream.gcount() < 24) {
        error = "truncated global header (file too short)";
        return nullptr;
    }

    ByteReader r(header, sizeof(header));

    std::uint32_t magic = r.u32_be();
    bool big_endian = false;
    bool nanoseconds = false;

    if (magic == 0xA1B2C3D4) {
        big_endian = true;
        nanoseconds = false;
    } else if (magic == 0xD4C3B2A1) {
        big_endian = false;
        nanoseconds = false;
    } else if (magic == 0xA1B23C4D) {
        big_endian = true;
        nanoseconds = true;
    } else if (magic == 0x4D3CB2A1) {
        big_endian = false;
        nanoseconds = true;
    } else if (magic == 0x0A0D0D0A) {
        error = "pcapng is not supported; save as 'Wireshark/tcpdump - pcap' or convert: editcap -F pcap in.pcapng out.pcap";
        return nullptr;
    } else {
        error = "not a pcap file (bad magic)";
        return nullptr;
    }

    std::uint16_t major = big_endian ? r.u16_be() : r.u16_le();
    if (major != 2) {
        error = "unsupported pcap version: " + std::to_string(major);
        return nullptr;
    }

    r.skip(10);

    std::uint32_t snaplen = big_endian ? r.u32_be() : r.u32_le();
    std::uint32_t network = big_endian ? r.u32_be() : r.u32_le();

    LinkType link = to_link_type(network & 0xFFFF);

    return std::unique_ptr<PcapFileReader>(new PcapFileReader(
        std::move(stream), big_endian, nanoseconds, snaplen, link, path));
}

StopReason PcapFileReader::run(PacketCallback on_packet) {
    while (true) {
        if (stop_requested()) {
            return StopReason::StoppedByUser;
        }

        auto offset = stream_.tellg();

        Byte rec_hdr[16];
        stream_.read(reinterpret_cast<char*>(rec_hdr), sizeof(rec_hdr));
        auto bytes_read = stream_.gcount();

        if (bytes_read == 0) {
            return StopReason::EndOfStream;
        }

        if (bytes_read < 16) {
            set_error("truncated record header at offset " + std::to_string(offset));
            return StopReason::Error;
        }

        ByteReader r(rec_hdr, sizeof(rec_hdr));
        std::uint32_t ts_sec   = read_u32(r);
        std::uint32_t ts_frac  = read_u32(r);
        std::uint32_t incl_len = read_u32(r);
        std::uint32_t orig_len = read_u32(r);

        std::uint32_t max_frac = nanoseconds_ ? 1'000'000'000u : 1'000'000u;
        if (ts_frac >= max_frac) {
            set_error("invalid timestamp fraction at offset " + std::to_string(offset));
            return StopReason::Error;
        }

        if (incl_len > MAX_RECORD_BYTES) {
            set_error("record length " + std::to_string(incl_len) + " exceeds limit at offset " + std::to_string(offset));
            return StopReason::Error;
        }

        if (incl_len > orig_len) {
            set_error("incl_len > orig_len at offset " + std::to_string(offset));
            return StopReason::Error;
        }

        std::int64_t total_us = static_cast<std::int64_t>(ts_sec) * 1'000'000 +
                                (nanoseconds_ ? (ts_frac / 1000) : ts_frac);

        RawPacket pkt(Timestamp{total_us}, nullptr, 0, orig_len);
        pkt.data.resize(incl_len);

        if (incl_len > 0) {
            stream_.read(reinterpret_cast<char*>(pkt.data.data()), incl_len);
            if (static_cast<std::uint32_t>(stream_.gcount()) < incl_len) {
                set_error("truncated packet data at offset " + std::to_string(offset));
                return StopReason::Error;
            }
        }

        on_packet(std::move(pkt));
    }
}

}