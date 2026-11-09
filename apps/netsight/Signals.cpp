#include "Signals.hpp"

#include <atomic>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <csignal>
#else
#include <cstring>
#include <signal.h>
#endif

namespace netsight {

namespace {

static_assert(std::atomic<bool>::is_always_lock_free, "std::atomic<bool> must be lock-free");

std::atomic<bool> g_stop_requested{false};

#ifdef _WIN32

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        g_stop_requested.store(true, std::memory_order_relaxed);
        return TRUE;
    default:
        return FALSE;
    }
}

void c_signal_handler(int sig) {
    g_stop_requested.store(true, std::memory_order_relaxed);
    std::signal(sig, c_signal_handler);
}

#else

void posix_signal_handler(int) {
    g_stop_requested.store(true, std::memory_order_relaxed);
}

#endif

}

#ifdef _WIN32

struct SignalGuard::Impl {
    void (*old_sigint)(int){SIG_DFL};
    void (*old_sigterm)(int){SIG_DFL};
    bool handler_registered{false};
};

SignalGuard::SignalGuard() : impl_(std::make_unique<Impl>()) {
    reset();
    if (SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        impl_->handler_registered = true;
    }
    impl_->old_sigint = std::signal(SIGINT, c_signal_handler);
    impl_->old_sigterm = std::signal(SIGTERM, c_signal_handler);
}

SignalGuard::~SignalGuard() noexcept {
    if (impl_) {
        if (impl_->handler_registered) {
            SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
            impl_->handler_registered = false;
        }
        if (impl_->old_sigint != SIG_ERR) {
            std::signal(SIGINT, impl_->old_sigint);
        }
        if (impl_->old_sigterm != SIG_ERR) {
            std::signal(SIGTERM, impl_->old_sigterm);
        }
    }
}

#else

struct SignalGuard::Impl {
    struct sigaction old_sigint{};
    struct sigaction old_sigterm{};
    bool active{false};
};

SignalGuard::SignalGuard() : impl_(std::make_unique<Impl>()) {
    reset();
    struct sigaction sa{};
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = posix_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, &impl_->old_sigint);
    sigaction(SIGTERM, &sa, &impl_->old_sigterm);
    impl_->active = true;
}

SignalGuard::~SignalGuard() noexcept {
    if (impl_ && impl_->active) {
        sigaction(SIGINT, &impl_->old_sigint, nullptr);
        sigaction(SIGTERM, &impl_->old_sigterm, nullptr);
        impl_->active = false;
    }
}

#endif

bool SignalGuard::stop_requested() noexcept {
    return g_stop_requested.load(std::memory_order_relaxed);
}

void SignalGuard::request_stop() noexcept {
    g_stop_requested.store(true, std::memory_order_relaxed);
}

void SignalGuard::reset() noexcept {
    g_stop_requested.store(false, std::memory_order_relaxed);
}

}