#include "netsight/capture/PcapLiveSource.hpp"
#include "netsight/capture/PcapRuntime.hpp"

#include <pcap.h>
#include <chrono>
#include <exception>
#include <memory>
#include <utility>

namespace netsight {

namespace {

struct CallbackContext {
    PacketCallback on_packet;
    pcap* handle{nullptr};
    bool failed{false};
    std::string error;
};

void pcap_trampoline(u_char* user, const struct pcap_pkthdr* hdr, const u_char* bytes) {
    auto* ctx = reinterpret_cast<CallbackContext*>(user);
    if (!ctx || ctx->failed) {
        return;
    }

    try {
        const auto sec = static_cast<std::int64_t>(hdr->ts.tv_sec);
        const auto usec = static_cast<std::int64_t>(hdr->ts.tv_usec);
        const std::int64_t us = sec * 1'000'000 + usec;

        ctx->on_packet(RawPacket(
            Timestamp{us},
            reinterpret_cast<const Byte*>(bytes),
            static_cast<std::size_t>(hdr->caplen),
            static_cast<std::uint32_t>(hdr->len)
        ));
    } catch (const std::exception& e) {
        ctx->failed = true;
        ctx->error = "packet callback threw: " + std::string(e.what());
        if (ctx->handle) {
            pcap_breakloop(ctx->handle);
        }
    } catch (...) {
        ctx->failed = true;
        ctx->error = "packet callback threw unknown exception";
        if (ctx->handle) {
            pcap_breakloop(ctx->handle);
        }
    }
}

}

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

StopReason PcapLiveSource::run(PacketCallback on_packet) {
    if (!handle_) {
        set_error("pcap handle is null");
        return StopReason::Error;
    }

    CallbackContext ctx{std::move(on_packet), handle_.get(), false, ""};
    auto last_refresh = std::chrono::steady_clock::now();

    while (!stop_requested()) {
        int rc = pcap_dispatch(
            handle_.get(),
            -1,
            pcap_trampoline,
            reinterpret_cast<u_char*>(&ctx));

        if (ctx.failed) {
            refresh_stats();
            set_error(ctx.error);
            return StopReason::Error;
        }

        if (rc == PCAP_ERROR) {
            refresh_stats();
            set_error("capture failed: " + std::string(pcap_geterr(handle_.get())));
            return StopReason::Error;
        }

        if (rc == PCAP_ERROR_BREAK && !stop_requested()) {
            continue;
        }

        auto now = std::chrono::steady_clock::now();
        if (now - last_refresh >= std::chrono::seconds(1)) {
            refresh_stats();
            last_refresh = now;
        }
    }

    refresh_stats();
    return StopReason::StoppedByUser;
}

void PcapLiveSource::on_stop_requested() {
    if (handle_) {
        pcap_breakloop(handle_.get());
    }
}

void PcapLiveSource::refresh_stats() noexcept {
    if (!handle_) {
        return;
    }

    struct pcap_stat s;
    if (pcap_stats(handle_.get(), &s) == 0) {
        const auto cur_recv = static_cast<std::uint32_t>(s.ps_recv);
        const auto cur_drop = static_cast<std::uint32_t>(s.ps_drop);
        const auto cur_ifdrop = static_cast<std::uint32_t>(s.ps_ifdrop);

        const std::uint32_t delta_recv = cur_recv - prev_recv_;
        const std::uint32_t delta_drop = cur_drop - prev_drop_;
        const std::uint32_t delta_ifdrop = cur_ifdrop - prev_ifdrop_;

        prev_recv_ = cur_recv;
        prev_drop_ = cur_drop;
        prev_ifdrop_ = cur_ifdrop;

        kernel_received_.fetch_add(delta_recv, std::memory_order_relaxed);
        kernel_dropped_.fetch_add(delta_drop, std::memory_order_relaxed);
        interface_dropped_.fetch_add(delta_ifdrop, std::memory_order_relaxed);
    }
}

}