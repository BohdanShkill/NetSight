#pragma once

#include <memory>

namespace netsight {

class SignalGuard {
public:
    SignalGuard();
    ~SignalGuard() noexcept;

    SignalGuard(const SignalGuard&) = delete;
    SignalGuard& operator=(const SignalGuard&) = delete;
    SignalGuard(SignalGuard&&) = delete;
    SignalGuard& operator=(SignalGuard&&) = delete;

    [[nodiscard]] static bool stop_requested() noexcept;
    static void request_stop() noexcept;
    static void reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}