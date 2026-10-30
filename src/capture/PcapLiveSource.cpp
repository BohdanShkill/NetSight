#include "netsight/capture/PcapLiveSource.hpp"
#include "netsight/capture/PcapRuntime.hpp"

#include <pcap.h>
#include <memory>
#include <utility>

namespace netsight {

void PcapLiveSource::PcapDeleter::operator()(pcap* p) const noexcept {
    if (p != nullptr) {
        pcap_close(p);
    }
}

PcapLiveSource::PcapLiveSource(
    std::unique_ptr<pcap, PcapDeleter> handle,
    LinkType link_type,
    std::uint32_t snaplen)
    : handle_(std::move(handle)),
      link_type_(link_type),
      snaplen_(snaplen) {}

PcapLiveSource::~PcapLiveSource() {
    stop();
}

CaptureStats PcapLiveSource::stats() const noexcept {
    return CaptureStats{
        kernel_received_.load(std::memory_order_relaxed),
        kernel_dropped_.load(std::memory_order_relaxed),
        interface_dropped_.load(std::memory_order_relaxed)
    };
}

std::unique_ptr<PcapLiveSource> PcapLiveSource::open(
    const std::string& device,
    const CaptureConfig& cfg,
    std::string& error) 
{
    if (device.empty()) {
        error = "device name cannot be empty";
        return nullptr;
    }

    if (cfg.snapshot_length < 64 || cfg.snapshot_length > 262144) {
        error = "snapshot_length must be between 64 and 262144 bytes, got: " + 
                std::to_string(cfg.snapshot_length);
        return nullptr;
    }

    if (cfg.read_timeout_ms == 0 || cfg.read_timeout_ms > 10000) {
        error = "read_timeout_ms must be between 1 and 10000 ms, got: " + 
                std::to_string(cfg.read_timeout_ms);
        return nullptr;
    }

    if (cfg.buffer_size_bytes < 65536 || cfg.buffer_size_bytes > 268435456) {
        error = "buffer_size_bytes must be between 64 KiB and 256 MiB, got: " + 
                std::to_string(cfg.buffer_size_bytes);
        return nullptr;
    }

    if (!ensure_pcap_loaded(error)) {
        return nullptr;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_t* h = pcap_create(device.c_str(), errbuf);
    if (!h) {
        error = errbuf[0] != '\0' ? errbuf : "pcap_create failed for device: " + device;
        return nullptr;
    }

    std::unique_ptr<pcap, PcapDeleter> handle_guard(h);

    pcap_set_snaplen(h, static_cast<int>(cfg.snapshot_length));
    pcap_set_promisc(h, cfg.promiscuous_mode ? 1 : 0);
    pcap_set_timeout(h, static_cast<int>(cfg.read_timeout_ms));
    pcap_set_buffer_size(h, static_cast<int>(cfg.buffer_size_bytes));

    int rc = pcap_activate(h);
    if (rc < 0) {
        std::string pcap_err = pcap_geterr(h);
        if (rc == PCAP_ERROR_PERM_DENIED) {
            error = "permission denied: " + pcap_err + 
                    " (hint: run as root or 'sudo setcap cap_net_raw,cap_net_admin=eip <bin>'; "
                    "on Windows check Npcap 'admin-only' install option)";
        } else if (rc == PCAP_ERROR_NO_SUCH_DEVICE) {
            error = "no such device: " + pcap_err + " (hint: see 'netsight list')";
        } else {
            error = "pcap_activate failed (" + std::to_string(rc) + "): " + pcap_err;
        }
        return nullptr;
    }

    std::string warning;
    if (rc > 0) {
        const char* warn_str = pcap_statustostr(rc);
        warning = "pcap_activate warning: " + std::string(warn_str ? warn_str : std::to_string(rc));
    }

    int dlt = pcap_datalink(h);
    LinkType link = link_type_from_dlt(static_cast<std::uint32_t>(dlt));
    if (link == LinkType::Unknown) {
        const char* dlt_name = pcap_datalink_val_to_name(dlt);
        error = "unsupported link type " + (dlt_name ? std::string(dlt_name) : std::to_string(dlt));
        return nullptr;
    }

    if (!cfg.bpf_filter.empty()) {
        bpf_u_int32 net = 0;
        bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
        char lookup_buf[PCAP_ERRBUF_SIZE] = "";
        
        if (pcap_lookupnet(device.c_str(), &net, &mask, lookup_buf) != 0) {
            mask = PCAP_NETMASK_UNKNOWN;
        }

        struct bpf_program prog;
        if (pcap_compile(h, &prog, cfg.bpf_filter.c_str(), 1, mask) != 0) {
            error = "invalid BPF filter: " + std::string(pcap_geterr(h));
            return nullptr;
        }

        std::unique_ptr<bpf_program, decltype(&pcap_freecode)> prog_guard(&prog, pcap_freecode);

        if (pcap_setfilter(h, &prog) != 0) {
            error = "pcap_setfilter failed: " + std::string(pcap_geterr(h));
            return nullptr;
        }
    }

    auto src = std::unique_ptr<PcapLiveSource>(
        new PcapLiveSource(std::move(handle_guard), link, cfg.snapshot_length));

    if (!warning.empty()) {
        src->set_error(warning);
    }

    return src;
}

StopReason PcapLiveSource::run(PacketCallback) {
    return StopReason::StoppedByUser;
}

void PcapLiveSource::on_stop_requested() {}

void PcapLiveSource::refresh_stats() noexcept {}

}