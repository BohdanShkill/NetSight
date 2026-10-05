#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include "netsight/core/Types.hpp"

namespace netsight {

    using PacketCallback = std::function<void(RawPacket)>;

    enum class StopReason {
        EndOfStream,
        StoppedByUser,
        Error
    };

    using CompletionCallback = std::function<void(StopReason)>;

    class IPacketSource
    {
    protected: IPacketSource() = default;
    public:
       
        virtual ~IPacketSource() = default;

        IPacketSource(const IPacketSource&) = delete;
        IPacketSource& operator=(const IPacketSource&) = delete;

        IPacketSource(IPacketSource&&) = delete;
        IPacketSource& operator=(IPacketSource&&) = delete;
        
        virtual bool start(PacketCallback on_packet, CompletionCallback on_complete) = 0;
        
        virtual bool is_running() const = 0;
        
        virtual void stop() = 0;
        
        virtual LinkType link_type() const = 0;
        
        virtual std::string last_error() const = 0;
    };
       
}