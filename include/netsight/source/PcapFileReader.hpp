#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "netsight/core/Types.hpp"
#include "netsight/source/ThreadedPacketSource.hpp"
#include "netsight/core/ByteReader.hpp"

namespace netsight {

class PcapFileReader final : public ThreadedPacketSource {
public:
    static std::unique_ptr<PcapFileReader> open(
        const std::filesystem::path& path, 
        std::string& error);

    ~PcapFileReader() override {
        stop(); 
    }

    LinkType link_type() const override {
        return link_type_;
    }

    std::uint32_t snaplen() const noexcept {
        return snaplen_;
    }

protected:
    StopReason run(PacketCallback on_packet) override;

private:
    PcapFileReader(
        std::ifstream stream,
        bool big_endian,
        bool nanoseconds,
        std::uint32_t snaplen,
        LinkType link_type,
        std::filesystem::path path);

    std::uint16_t read_u16(ByteReader& r) const noexcept;
    std::uint32_t read_u32(ByteReader& r) const noexcept;

    std::ifstream stream_;
    bool big_endian_{false};
    bool nanoseconds_{false};
    std::uint32_t snaplen_{0};
    LinkType link_type_{LinkType::Unknown};
    std::filesystem::path path_;

    static constexpr std::uint32_t MAX_RECORD_BYTES = 262144;

};

}