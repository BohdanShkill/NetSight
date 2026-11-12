#pragma once

#include "netsight/core/IpAddress.hpp"

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace netsight {

enum class ExitCode : int {
    Ok = 0,
    RuntimeError = 1,
    UsageError = 2
};

enum class CommandKind : std::uint8_t {
    None,
    List,
    Capture,
    Aggregate
};

struct CaptureCliOptions {
    std::optional<std::string> interface_arg{};
    std::optional<std::string> read_file{};
    std::string bpf_filter{};
    std::optional<IpAddress> filter_ip{};
    std::string filter_ip_raw{};
    std::optional<std::uint16_t> filter_port{};
    std::optional<double> duration_seconds{};
    std::optional<std::uint64_t> max_packets{};
    std::size_t queue_size{8192};
    std::uint32_t snaplen{65535};
    bool promiscuous{true};
    std::optional<std::string> csv_prefix{};
    std::optional<std::uint16_t> api_port{};
    std::string api_host{"127.0.0.1"};
    std::string api_token{};
    bool quiet{false};
};

struct AggregateCliOptions {
    std::vector<std::string> agents{};
    std::string api_token{};
    double interval_seconds{1.0};
    std::uint32_t timeout_ms{1000};
    std::uint64_t rounds{0};
    std::size_t min_agents{2};
    double syn_threshold{100.0};
    double pps_threshold{500.0};
    double syn_ack_ratio{0.25};
    double proto_share{0.70};
    double port_share{0.60};
    std::optional<std::string> csv_file{};
    bool quiet{false};
};

struct CliParseResult {
    ExitCode exit_code{ExitCode::Ok};
    CommandKind command{CommandKind::None};
    CaptureCliOptions capture{};
    AggregateCliOptions aggregate{};
};

CliParseResult parse_cli(int argc, const char* const* argv, std::ostream& out, std::ostream& err);
CliParseResult parse_cli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

}