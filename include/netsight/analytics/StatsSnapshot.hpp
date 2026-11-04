#pragma once

#include "netsight/analytics/Alert.hpp"
#include "netsight/core/IpAddress.hpp"
#include "netsight/core/Types.hpp"
#include "netsight/parser/ParsedPacket.hpp"

#include <cstdint>
#include <vector>

namespace netsight {

struct TrafficCounter {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};

    void add(std::uint64_t wire_bytes) noexcept {
        ++packets;
        bytes += wire_bytes;
    }

    bool operator==(const TrafficCounter& rhs) const noexcept {
        return packets == rhs.packets && bytes == rhs.bytes;
    }

    bool operator!=(const TrafficCounter& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct ParseStatusCounts {
    std::uint64_t ok{0};
    std::uint64_t truncated{0};
    std::uint64_t malformed{0};
    std::uint64_t unsupported_link{0};

    bool operator==(const ParseStatusCounts& rhs) const noexcept {
        return ok == rhs.ok &&
               truncated == rhs.truncated &&
               malformed == rhs.malformed &&
               unsupported_link == rhs.unsupported_link;
    }

    bool operator!=(const ParseStatusCounts& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct NetworkProtocolCounts {
    TrafficCounter ipv4{};
    TrafficCounter ipv6{};
    TrafficCounter arp{};
    TrafficCounter other{};
    std::uint64_t vlan_tagged_packets{0};
    std::uint64_t fragmented_packets{0};

    bool operator==(const NetworkProtocolCounts& rhs) const noexcept {
        return ipv4 == rhs.ipv4 &&
               ipv6 == rhs.ipv6 &&
               arp == rhs.arp &&
               other == rhs.other &&
               vlan_tagged_packets == rhs.vlan_tagged_packets &&
               fragmented_packets == rhs.fragmented_packets;
    }

    bool operator!=(const NetworkProtocolCounts& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct TransportProtocolCounts {
    TrafficCounter tcp{};
    TrafficCounter udp{};
    TrafficCounter icmp{};
    TrafficCounter icmpv6{};
    TrafficCounter other{};
    TrafficCounter none{};

    bool operator==(const TransportProtocolCounts& rhs) const noexcept {
        return tcp == rhs.tcp &&
               udp == rhs.udp &&
               icmp == rhs.icmp &&
               icmpv6 == rhs.icmpv6 &&
               other == rhs.other &&
               none == rhs.none;
    }

    bool operator!=(const TransportProtocolCounts& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct TalkerEntry {
    IpAddress ip{};
    std::uint64_t packets{0};
    std::uint64_t bytes{0};

    bool operator==(const TalkerEntry& rhs) const noexcept {
        return ip == rhs.ip && packets == rhs.packets && bytes == rhs.bytes;
    }

    bool operator!=(const TalkerEntry& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct PortEntry {
    std::uint16_t port{0};
    std::uint64_t packets{0};
    std::uint64_t bytes{0};

    bool operator==(const PortEntry& rhs) const noexcept {
        return port == rhs.port && packets == rhs.packets && bytes == rhs.bytes;
    }

    bool operator!=(const PortEntry& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct DropCounters {
    std::uint64_t filtered_out{0};
    std::uint64_t queue_dropped{0};
    std::uint64_t kernel_dropped{0};
    std::uint64_t interface_dropped{0};
    std::uint64_t untracked_talker_packets{0};
    std::uint64_t untracked_port_packets{0};
    std::uint64_t untracked_syn_targets{0};

    bool operator==(const DropCounters& rhs) const noexcept {
        return filtered_out == rhs.filtered_out &&
               queue_dropped == rhs.queue_dropped &&
               kernel_dropped == rhs.kernel_dropped &&
               interface_dropped == rhs.interface_dropped &&
               untracked_talker_packets == rhs.untracked_talker_packets &&
               untracked_port_packets == rhs.untracked_port_packets &&
               untracked_syn_targets == rhs.untracked_syn_targets;
    }

    bool operator!=(const DropCounters& rhs) const noexcept {
        return !(*this == rhs);
    }
};

struct StatsSnapshot {
    std::uint64_t snapshot_seq{0};
    std::uint64_t total_packets{0};
    std::uint64_t total_wire_bytes{0};
    std::uint64_t total_captured_bytes{0};
    Timestamp first_packet_ts{0};
    Timestamp last_packet_ts{0};
    double duration_seconds{0.0};
    double packets_per_second{0.0};
    double bytes_per_second{0.0};
    ParseStatusCounts status{};
    NetworkProtocolCounts l3{};
    TransportProtocolCounts l4{};
    DropCounters drops{};
    std::vector<TalkerEntry> top_talkers{};
    std::vector<PortEntry> top_ports{};
    std::vector<Alert> alerts{};
};

}