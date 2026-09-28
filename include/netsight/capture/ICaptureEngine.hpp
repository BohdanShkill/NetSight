#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include "netsight/core/Types.hpp"

namespace netsight {
    struct NetworkInterface
    {
        std::string name;
        std::string description;
        std::string ipv4_address;
        bool is_loopback = false;
        bool up = true;
    };
    struct CaptureConfig
    {
        uint32_t snapshot_lenght = 65535;
        bool primiscuous_mode = true;
        uint32_t read_timeout_ms = 1000;
        std::string bpf_filter = "";
    };
    using PacketCallBack = std::function<void(RawPacket)>;
    
}