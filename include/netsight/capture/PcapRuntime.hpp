#pragma once

#include <cstdint>
#include <string>

#include "netsight/core/Types.hpp"

namespace netsight {

    bool ensure_pcap_loaded(std::string& error);
    
    bool validate_bpf(
    const std::string& expr,
    LinkType link,
    std::uint32_t snaplen,
    std::string& error);

}