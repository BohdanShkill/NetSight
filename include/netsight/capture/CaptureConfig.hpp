#pragma once

#include <cstdint>
#include <string>

namespace netsight {

    struct CaptureConfig {
        std::uint32_t snapshot_length = 65535;
        bool promiscuous_mode = true;
        std::uint32_t read_timeout_ms = 250;
        std::string bpf_filter = "";
        std::uint32_t buffer_size_bytes = 4 * 1024 * 1024;
    };

}