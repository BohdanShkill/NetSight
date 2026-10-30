#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "netsight/capture/CaptureConfig.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/source/ThreadedPacketSource.hpp"

struct pcap;

namespace netsight {

struct CaptureStats {
    std::uint64_t kernel_received{0};
    std::uint64_t kernel_dropped{0};
    std::uint64_t interface_dropped{0};
};

class PcapLiveSource final : public ThreadedPacketSource {
public:
    static std::unique_ptr<PcapLiveSource> open(
        const std::string& device,
        const CaptureConfig& cfg,
        std::string& error);

    ~PcapLiveSource() override;

    LinkType link_type() const override {
        return link_type_;
    }

    std::uint32_t snaplen() const noexcept {
        return snaplen_;
    }

    CaptureStats stats() const noexcept;

protected:
    StopReason run(PacketCallback on_packet) override;
    void on_stop_requested() override;

private:
    struct PcapDeleter {
        void operator()(pcap* p) const noexcept;
    };

    PcapLiveSource(
        std::unique_ptr<pcap, PcapDeleter> handle,
        LinkType link_type,
        std::uint32_t snaplen);

    std::unique_ptr<pcap, PcapDeleter> handle_;
    LinkType link_type_{LinkType::Unknown};
    std::uint32_t snaplen_{0};

    std::atomic<std::uint64_t> kernel_received_{0};
    std::atomic<std::uint64_t> kernel_dropped_{0};
    std::atomic<std::uint64_t> interface_dropped_{0};

    std::uint32_t prev_recv_{0};
    std::uint32_t prev_drop_{0};
    std::uint32_t prev_ifdrop_{0};

    void refresh_stats() noexcept;
};

}