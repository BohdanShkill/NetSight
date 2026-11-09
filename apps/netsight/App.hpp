#pragma once

#include "Cli.hpp"
#include "Signals.hpp"

#include "netsight/capture/CaptureConfig.hpp"
#include "netsight/capture/Devices.hpp"
#include "netsight/source/IPacketSource.hpp"

#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace netsight {

struct AppEnv {
    std::istream& in{std::cin};
    std::ostream& out{std::cout};
    std::ostream& err{std::cerr};
    bool stdin_is_tty{false};
    bool stdout_is_tty{false};
    std::function<std::vector<NetworkInterface>(std::string&)> list_interfaces_fn{&list_interfaces};
    std::function<bool()> stop_requested_fn{&SignalGuard::stop_requested};
    std::function<void(std::uint16_t)> on_api_listening{};
    std::function<std::unique_ptr<IPacketSource>(const std::string&, const CaptureConfig&, std::string&)> open_live_source_fn{};
};

[[nodiscard]] ExitCode run_netsight(int argc, const char* const* argv, AppEnv& env);
[[nodiscard]] ExitCode run_netsight(const std::vector<std::string>& args, AppEnv& env);

}