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

    /**
     * @brief A polymorphic interface for streaming packet capture.
     *
     * @par Streaming contract (K1–K8):
     * - **K1**: start() does not block the call. Starts a background capture thread and returns true,
     *   or returns false if the source is not initialised, is already running, or an empty callback has been passed.
     * - **K2**: on_packet is called sequentially and exclusively from the source’s worker thread.
     * - **K3**: on_complete is executed exactly once per successful launch from the worker thread
     *   after the last packet has been processed.
     * - **K4**: stop() is idempotent and thread-safe. A call from an external thread blocks execution
     *   until the worker thread has fully completed.
     * - **K5**: Calling stop() within a callback (the same thread) initiates a stop, but does not call join() on itself.
     * - **K6**: Exceptions thrown from callbacks are intercepted by the worker thread, interrupt execution
     *   and pass StopReason::Error to the termination.
     * - **K7**: The destructor must call stop() to ensure deterministic resource release.
     * - **K8**: Single-pass lifecycle: a subsequent call to start() after termination returns false.
     */

    class IPacketSource
    {
    protected: IPacketSource() = default;
    public:
       /**
        * @brief Ensures that the worker thread (K7) stops in a deterministic manner.
        */
        virtual ~IPacketSource() = default;

        IPacketSource(const IPacketSource&) = delete;
        IPacketSource& operator=(const IPacketSource&) = delete;

        IPacketSource(IPacketSource&&) = delete;
        IPacketSource& operator=(IPacketSource&&) = delete;
        /**
         * @brief Starts asynchronous packet reading (K1).
         * @param on_packet Packet handling callback (K2).
         * @param on_complete Callback for stream completion (K3, K6).
         * @return true if the stream started successfully; false in the event of a validation error or a repeat call (K8).
         */
        virtual bool start(PacketCallback on_packet, CompletionCallback on_complete) = 0;
        /**
         * @brief Checks whether the capture thread is currently active.
         */
        virtual bool is_running() const = 0;
        /**
         * @brief Stops the capture (K4, K5).
         * @note This method is thread-safe and idempotent.
         */
        virtual void stop() = 0;
        /**
         * @brief Returns the channel level type of the current source.
         */
        virtual LinkType link_type() const = 0;
        /**
         * @brief Returns a text description of the source’s most recent error.
         */
        virtual std::string last_error() const = 0;
    };
       
}