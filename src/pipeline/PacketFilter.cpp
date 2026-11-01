#include "netsight/pipeline/PacketFilter.hpp"
namespace netsight {
bool PacketFilter::empty() const noexcept {
    return !ip.has_value() && !port.has_value();
}
bool PacketFilter::matches(const ParsedPacket& packet) const noexcept {
    if (ip.has_value()) {
        if (packet.src_ip != *ip && packet.dst_ip != *ip) {
            return false;
        }
    }
    if (port.has_value()) {
        if (packet.transport != TransportProtocol::TCP && packet.transport != TransportProtocol::UDP) {
            return false;
        }
        if (packet.src_port != *port && packet.dst_port != *port) {
            return false;
        }
    }
    return true;
}
}