#pragma once

#include "netsight/core/Types.hpp"

#include <array>
#include <cstdint>
#include <type_traits>

namespace netsight {

enum class ParseStatus {
    Ok,                   
    Truncated,            
    UnsupportedLinkType   
};

struct ParsedPacket {
    Timestamp timestamp{};
    uint32_t wire_length{0};        
    uint32_t captured_length{0};    
    LinkType link_type{LinkType::Unknown};

    ParseStatus status{ParseStatus::Truncated}; 

    uint16_t ether_type{0};         
    uint8_t vlan_count{0};          
    std::array<uint16_t, 2> vlan_ids{0, 0}; 

    NetworkProtocol network{NetworkProtocol::None};
    uint32_t l3_offset{0};          
};

static_assert(std::is_trivially_copyable_v<ParsedPacket>,
              "ParsedPacket must be trivially copyable (zero heap allocations)");

}