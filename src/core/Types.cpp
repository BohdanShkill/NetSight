#include "netsight/core/Types.hpp"

namespace netsight{

    std::string to_string(ProtocolType proto) {
        switch (proto)
        {
        case ProtocolType::Unknown:
            return "Unknown";
        case ProtocolType::TCP:
            return "TCP";
        case ProtocolType::UDP:
            return "UDP";
        case ProtocolType::ICMP:
            return "ICMP";
        case ProtocolType::ICMPv6:
            return "ICMPv6";
        case ProtocolType::Other:
            return "Other";  
        }
        return "Unknown";
    }

    std::string to_string(LinkType link) {
        switch (link)
        {
        case LinkType::Null:
            return "Null";
        case LinkType::Ethernet:
            return "Ethernet";
        case LinkType::Loop:
            return "Loop";
        case LinkType::LinuxSll:
            return "LinuxSll";
        case LinkType::Unknown:
            return "Unknown";
        }
    return "Unknown";  
    }

    LinkType link_type_from_dlt(std::uint32_t val) noexcept {
    switch (val) {
        case 0:   return LinkType::Null;
        case 1:   return LinkType::Ethernet;
        case 108: return LinkType::Loop;
        case 113: return LinkType::LinuxSll;
        default:  return LinkType::Unknown;
    }
}

}