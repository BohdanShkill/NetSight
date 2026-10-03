#include "netsight/core/Types.hpp"

namespace netsight{

    std::string to_string(ProtocolType protocol){
        switch (protocol)
        {
        case ProtocolType::TCP:
            return "TCP";
        case ProtocolType::UDP:
            return "UDP";
        case ProtocolType::ICMP:
            return "ICMP";
        case ProtocolType::ICMPv6:
            return "ICMPv6";
        default:
            return "Unknown";
        }
    }

    std::string to_string(LinkType link_type){
        switch (link_type)
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

}