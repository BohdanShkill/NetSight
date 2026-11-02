#include "netsight/analytics/StatsAggregator.hpp"

#include <algorithm>
#include <chrono>
#include <vector>

namespace netsight {

StatsAggregator::StatsAggregator(StatsConfig cfg)
    : cfg_(cfg),
      published_(std::make_shared<const StatsSnapshot>()) {
    talkers_.reserve(cfg_.max_tracked_talkers);
    ports_.reserve(cfg_.max_tracked_ports);
}

void StatsAggregator::record(const ParsedPacket& pkt) {
    ++total_packets_;
    total_wire_bytes_ += pkt.wire_length;
    total_captured_bytes_ += pkt.captured_length;

    if (total_packets_ == 1) {
        first_packet_ts_ = pkt.timestamp;
        last_packet_ts_ = pkt.timestamp;
    } else {
        if (pkt.timestamp < first_packet_ts_) {
            first_packet_ts_ = pkt.timestamp;
        }
        if (pkt.timestamp > last_packet_ts_) {
            last_packet_ts_ = pkt.timestamp;
        }
    }

    switch (pkt.status) {
        case ParseStatus::Ok:
            ++status_.ok;
            break;
        case ParseStatus::Truncated:
            ++status_.truncated;
            return;
        case ParseStatus::Malformed:
            ++status_.malformed;
            return;
        case ParseStatus::UnsupportedLinkType:
            ++status_.unsupported_link;
            return;
    }

    if (pkt.vlan_count > 0) {
        ++l3_.vlan_tagged_packets;
    }
    if (pkt.is_fragment) {
        ++l3_.fragmented_packets;
    }

    switch (pkt.network) {
        case NetworkProtocol::IPv4:
            l3_.ipv4.add(pkt.wire_length);
            break;
        case NetworkProtocol::IPv6:
            l3_.ipv6.add(pkt.wire_length);
            break;
        case NetworkProtocol::Arp:
            l3_.arp.add(pkt.wire_length);
            break;
        case NetworkProtocol::Other:
        case NetworkProtocol::None:
        default:
            l3_.other.add(pkt.wire_length);
            break;
    }

    switch (pkt.transport) {
        case TransportProtocol::TCP:
            l4_.tcp.add(pkt.wire_length);
            break;
        case TransportProtocol::UDP:
            l4_.udp.add(pkt.wire_length);
            break;
        case TransportProtocol::ICMP:
            l4_.icmp.add(pkt.wire_length);
            break;
        case TransportProtocol::ICMPv6:
            l4_.icmpv6.add(pkt.wire_length);
            break;
        case TransportProtocol::Other:
            l4_.other.add(pkt.wire_length);
            break;
        case TransportProtocol::None:
        default:
            l4_.none.add(pkt.wire_length);
            break;
    }

    if (pkt.src_ip.is_valid()) {
        auto it = talkers_.find(pkt.src_ip);
        if (it != talkers_.end()) {
            it->second.add(pkt.wire_length);
        } else if (talkers_.size() < cfg_.max_tracked_talkers) {
            TrafficCounter counter{};
            counter.add(pkt.wire_length);
            talkers_.emplace(pkt.src_ip, counter);
        } else {
            ++untracked_talker_packets_;
        }
    }

    if (pkt.transport == TransportProtocol::TCP || pkt.transport == TransportProtocol::UDP) {
        auto it = ports_.find(pkt.dst_port);
        if (it != ports_.end()) {
            it->second.add(pkt.wire_length);
        } else if (ports_.size() < cfg_.max_tracked_ports) {
            TrafficCounter counter{};
            counter.add(pkt.wire_length);
            ports_.emplace(pkt.dst_port, counter);
        } else {
            ++untracked_port_packets_;
        }
    }
}

StatsSnapshot StatsAggregator::build_snapshot(const DropCounters& external_drops) const {
    StatsSnapshot snap{};
    snap.total_packets = total_packets_;
    snap.total_wire_bytes = total_wire_bytes_;
    snap.total_captured_bytes = total_captured_bytes_;
    snap.first_packet_ts = first_packet_ts_;
    snap.last_packet_ts = last_packet_ts_;
    snap.status = status_;
    snap.l3 = l3_;
    snap.l4 = l4_;

    snap.drops = external_drops;
    snap.drops.untracked_talker_packets = untracked_talker_packets_;
    snap.drops.untracked_port_packets = untracked_port_packets_;

    const auto elapsed_us = (last_packet_ts_ - first_packet_ts_).count();
    if (total_packets_ > 1 && elapsed_us > 0) {
        const double secs = static_cast<double>(elapsed_us) / 1'000'000.0;
        snap.duration_seconds = secs;
        snap.packets_per_second = static_cast<double>(total_packets_) / secs;
        snap.bytes_per_second = static_cast<double>(total_wire_bytes_) / secs;
    }

    if (cfg_.top_n > 0 && !talkers_.empty()) {
        std::vector<TalkerEntry> entries;
        entries.reserve(talkers_.size());
        for (const auto& [ip, counter] : talkers_) {
            entries.push_back(TalkerEntry{ip, counter.packets, counter.bytes});
        }
        const std::size_t k = std::min(cfg_.top_n, entries.size());
        std::partial_sort(
            entries.begin(),
            entries.begin() + k,
            entries.end(),
            [](const TalkerEntry& a, const TalkerEntry& b) noexcept {
                if (a.bytes != b.bytes) return a.bytes > b.bytes;
                if (a.packets != b.packets) return a.packets > b.packets;
                return a.ip < b.ip;
            }
        );
        entries.resize(k);
        snap.top_talkers = std::move(entries);
    }

    if (cfg_.top_n > 0 && !ports_.empty()) {
        std::vector<PortEntry> entries;
        entries.reserve(ports_.size());
        for (const auto& [port, counter] : ports_) {
            entries.push_back(PortEntry{port, counter.packets, counter.bytes});
        }
        const std::size_t k = std::min(cfg_.top_n, entries.size());
        std::partial_sort(
            entries.begin(),
            entries.begin() + k,
            entries.end(),
            [](const PortEntry& a, const PortEntry& b) noexcept {
                if (a.bytes != b.bytes) return a.bytes > b.bytes;
                if (a.packets != b.packets) return a.packets > b.packets;
                return a.port < b.port;
            }
        );
        entries.resize(k);
        snap.top_ports = std::move(entries);
    }

    return snap;
}

std::shared_ptr<const StatsSnapshot> StatsAggregator::publish(const DropCounters& external_drops) {
    StatsSnapshot snap = build_snapshot(external_drops);
    snap.snapshot_seq = ++seq_;
    auto ptr = std::make_shared<const StatsSnapshot>(std::move(snap));
    {
        std::lock_guard<std::mutex> lock(snapshot_mutex_);
        published_ = ptr;
    }
    return ptr;
}

std::shared_ptr<const StatsSnapshot> StatsAggregator::latest_snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(snapshot_mutex_);
    return published_;
}

std::size_t StatsAggregator::tracked_talker_count() const noexcept {
    return talkers_.size();
}

std::size_t StatsAggregator::tracked_port_count() const noexcept {
    return ports_.size();
}

void StatsAggregator::reset() {
    total_packets_ = 0;
    total_wire_bytes_ = 0;
    total_captured_bytes_ = 0;
    first_packet_ts_ = Timestamp{0};
    last_packet_ts_ = Timestamp{0};
    status_ = ParseStatusCounts{};
    l3_ = NetworkProtocolCounts{};
    l4_ = TransportProtocolCounts{};
    talkers_.clear();
    ports_.clear();
    untracked_talker_packets_ = 0;
    untracked_port_packets_ = 0;
    seq_ = 0;

    auto empty_snap = std::make_shared<const StatsSnapshot>();
    {
        std::lock_guard<std::mutex> lock(snapshot_mutex_);
        published_ = std::move(empty_snap);
    }
}

}