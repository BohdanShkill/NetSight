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

    using PacketCallback = std::function<void(RawPacket)>;

    class ICaptureEngine
    {
    public:
        virtual ~ICaptureEngine() = default;

        ICaptureEngine(const ICaptureEngine&) = default;
        ICaptureEngine& operator=(const ICaptureEngine&) = delete;

        ICaptureEngine(ICaptureEngine&&) = default;
        ICaptureEngine& operator=(ICaptureEngine&&) = default;

        ICaptureEngine() = default;

        virtual std::vector<NetworkInterface> list_interfaces() = 0;
        virtual bool is_running() const = 0;
        virtual bool open(const std::string&, const CaptureConfig&) = 0;
        virtual bool set_filter(const std::string&) = 0;
        virtual bool start(PacketCallback) = 0;
        virtual void stop() = 0;
        virtual std::string get_last_error() const = 0;
    };
       
}