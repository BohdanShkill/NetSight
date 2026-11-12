#include "Cli.hpp"

#include <CLI/CLI.hpp>

#include <charconv>
#include <cmath>
#include <limits>
#include <ostream>
#include <string_view>

#ifndef NETSIGHT_VERSION
#define NETSIGHT_VERSION "0.1.0"
#endif

namespace netsight {

namespace {

bool is_valid_agent_endpoint(std::string_view ep) {
    if (ep.empty()) {
        return false;
    }
    if (ep.rfind("http://", 0) == 0) {
        ep.remove_prefix(7);
    } else if (ep.rfind("https://", 0) == 0) {
        ep.remove_prefix(8);
    }
    const auto colon_pos = ep.rfind(':');
    if (colon_pos == std::string_view::npos) {
        return false;
    }
    const auto host = ep.substr(0, colon_pos);
    const auto port_str = ep.substr(colon_pos + 1);
    if (host.empty() || port_str.empty()) {
        return false;
    }
    int p = 0;
    auto [ptr, ec] = std::from_chars(port_str.data(), port_str.data() + port_str.size(), p);
    if (ec != std::errc{} || ptr != port_str.data() + port_str.size() || p <= 0 || p > 65535) {
        return false;
    }
    return true;
}

}

CliParseResult parse_cli(int argc, const char* const* argv, std::ostream& out, std::ostream& err) {
    CLI::App app{"NetSight - Network traffic analyzer and anomaly detector", "netsight"};
    app.set_version_flag("-v,--version", std::string("netsight ") + NETSIGHT_VERSION);
    app.require_subcommand(1);

    auto* list_cmd = app.add_subcommand("list", "List available network capture interfaces");

    auto* cap_cmd = app.add_subcommand("capture", "Capture live traffic or analyze a .pcap file");

    std::string interface_arg_val;
    auto* opt_iface = cap_cmd->add_option("-i,--interface", interface_arg_val, "Interface name or index");

    std::string read_file_val;
    auto* opt_file = cap_cmd->add_option("-r,--read-file", read_file_val, "Path to .pcap file to read");

    opt_iface->excludes(opt_file);
    opt_file->excludes(opt_iface);

    std::string bpf_filter_val;
    auto* opt_bpf = cap_cmd->add_option("--bpf", bpf_filter_val, "BPF filter expression (live capture only)")
                            ->excludes(opt_file);

    int snaplen_val = 65535;
    cap_cmd->add_option("--snaplen", snaplen_val, "Snapshot length in bytes (64..262144)")
           ->check(CLI::Range(64, 262144))
           ->excludes(opt_file);

    bool no_promisc = false;
    cap_cmd->add_flag("--no-promisc", no_promisc, "Disable promiscuous mode")
           ->excludes(opt_file);

    std::string filter_ip_raw_val;
    auto* opt_f_ip = cap_cmd->add_option("--filter-ip", filter_ip_raw_val, "Filter packets by IPv4 or IPv6 address");

    int filter_port_val = 0;
    auto* opt_f_port = cap_cmd->add_option("--filter-port", filter_port_val, "Filter packets by L4 port (1..65535)")
                              ->check(CLI::Range(1, 65535));

    double duration_val = 0.0;
    auto* opt_dur = cap_cmd->add_option("--duration", duration_val, "Auto-stop capture after N seconds (> 0.0)");

    std::int64_t count_val = 0;
    auto* opt_count = cap_cmd->add_option("--count", count_val, "Auto-stop capture after N packets (>= 1)")
                             ->check(CLI::Range(std::int64_t{1}, std::numeric_limits<std::int64_t>::max()));

    std::int64_t queue_size_val = 8192;
    cap_cmd->add_option("--queue-size", queue_size_val, "Internal packet queue capacity (1..1048576)")
           ->check(CLI::Range(std::int64_t{1}, std::int64_t{1048576}));

    std::string csv_prefix_val;
    auto* opt_csv = cap_cmd->add_option("--csv", csv_prefix_val, "Prefix for output CSV files");

    int api_port_val = 0;
    auto* opt_aport = cap_cmd->add_option("--api-port", api_port_val, "Enable REST API server on specified port (0..65535)")
                             ->check(CLI::Range(0, 65535));

    std::string api_host_val = "127.0.0.1";
    cap_cmd->add_option("--api-host", api_host_val, "Host/IP to bind REST API server")
           ->needs(opt_aport);

    std::string api_token_val;
    cap_cmd->add_option("--api-token", api_token_val, "Bearer token for REST API")
           ->needs(opt_aport);

    bool quiet_val = false;
    cap_cmd->add_flag("-q,--quiet", quiet_val, "Suppress non-essential console output");

    auto* agg_cmd = app.add_subcommand("aggregate", "Aggregate metrics from multiple NetSight agents for distributed DDoS detection");

    std::vector<std::string> agg_agents_val;
    auto* opt_agg_agents = agg_cmd->add_option("-a,--agent", agg_agents_val, "Agent endpoint in host:port format (can specify multiple)")
                                   ->expected(1, -1);

    std::string agg_token_val;
    agg_cmd->add_option("--api-token", agg_token_val, "Bearer token for authenticating with agents");

    double agg_interval_val = 1.0;
    auto* opt_agg_interval = agg_cmd->add_option("--interval", agg_interval_val, "Interval in seconds between polling rounds (> 0.0)");

    std::uint32_t agg_timeout_ms_val = 1000;
    agg_cmd->add_option("--timeout-ms", agg_timeout_ms_val, "Timeout in milliseconds for agent HTTP polling (50..60000)")
           ->check(CLI::Range(std::uint32_t{50}, std::uint32_t{60000}));

    std::int64_t agg_rounds_val = 0;
    agg_cmd->add_option("--rounds", agg_rounds_val, "Number of polling rounds (0 = run indefinitely)")
           ->check(CLI::Range(std::int64_t{0}, std::numeric_limits<std::int64_t>::max()));

    std::int64_t agg_min_agents_val = 2;
    agg_cmd->add_option("--min-agents", agg_min_agents_val, "Minimum witness agents to correlate a distributed attack (>= 1)")
           ->check(CLI::Range(std::int64_t{1}, std::numeric_limits<std::int64_t>::max()));

    double agg_syn_thresh_val = 100.0;
    auto* opt_agg_syn = agg_cmd->add_option("--syn-threshold", agg_syn_thresh_val, "Global threshold for distributed SYN flood in SYN/s (> 0.0)");

    double agg_pps_thresh_val = 500.0;
    auto* opt_agg_pps = agg_cmd->add_option("--pps-threshold", agg_pps_thresh_val, "Global volumetric threshold in packets/s (> 0.0)");

    double agg_syn_ack_ratio_val = 0.25;
    auto* opt_agg_syn_ack = agg_cmd->add_option("--syn-ack-ratio", agg_syn_ack_ratio_val, "Maximum SYN/ACK ratio threshold (0.0 < ratio <= 1.0)")
                                    ->check(CLI::Range(0.0, 1.0));

    double agg_proto_share_val = 0.70;
    auto* opt_agg_proto_share = agg_cmd->add_option("--proto-share", agg_proto_share_val, "Dominant protocol share threshold (0.0 < share <= 1.0)")
                                        ->check(CLI::Range(0.0, 1.0));

    double agg_port_share_val = 0.60;
    auto* opt_agg_port_share = agg_cmd->add_option("--port-share", agg_port_share_val, "Target port concentration share threshold (0.0 < share <= 1.0)")
                                       ->check(CLI::Range(0.0, 1.0));

    std::string agg_csv_val;
    auto* opt_agg_csv = agg_cmd->add_option("--csv", agg_csv_val, "Path to output CSV file for recording global metrics per round");

    bool agg_quiet_val = false;
    agg_cmd->add_flag("-q,--quiet", agg_quiet_val, "Suppress periodic console output");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        int rc = app.exit(e, out, err);
        if (rc != 0 && opt_bpf->count() > 0 && opt_file->count() > 0) {
            err << "Hint: --bpf is only supported for live capture (-i). For offline pcap (-r), use --filter-ip or --filter-port.\n";
        }
        return {rc == 0 ? ExitCode::Ok : ExitCode::UsageError, CommandKind::None, {}, {}};
    }

    if (list_cmd->parsed()) {
        return {ExitCode::Ok, CommandKind::List, {}, {}};
    }

    if (cap_cmd->parsed()) {
        CaptureCliOptions opts;

        if (opt_iface->count() > 0) {
            opts.interface_arg = interface_arg_val;
        }

        if (opt_file->count() > 0) {
            opts.read_file = read_file_val;
        }

        opts.bpf_filter = bpf_filter_val;
        opts.snaplen = static_cast<std::uint32_t>(snaplen_val);
        opts.promiscuous = !no_promisc;

        if (opt_f_ip->count() > 0) {
            auto parsed_ip = parse_ip_address(filter_ip_raw_val);
            if (!parsed_ip.has_value()) {
                err << "Error: invalid IP address filter: " << filter_ip_raw_val << '\n';
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
            opts.filter_ip = parsed_ip;
            opts.filter_ip_raw = filter_ip_raw_val;
        }

        if (opt_f_port->count() > 0) {
            opts.filter_port = static_cast<std::uint16_t>(filter_port_val);
        }

        if (opt_dur->count() > 0) {
            if (!std::isfinite(duration_val) || duration_val <= 0.0) {
                err << "Error: --duration must be a finite positive number\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
            opts.duration_seconds = duration_val;
        }

        if (opt_count->count() > 0) {
            opts.max_packets = static_cast<std::uint64_t>(count_val);
        }

        opts.queue_size = static_cast<std::size_t>(queue_size_val);

        if (opt_csv->count() > 0) {
            if (csv_prefix_val.empty()) {
                err << "Error: --csv prefix cannot be empty\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
            opts.csv_prefix = csv_prefix_val;
        }

        if (opt_aport->count() > 0) {
            opts.api_port = static_cast<std::uint16_t>(api_port_val);
            if (api_host_val.empty()) {
                err << "Error: --api-host cannot be empty\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
            opts.api_host = api_host_val;
            opts.api_token = api_token_val;
        }

        opts.quiet = quiet_val;

        return {ExitCode::Ok, CommandKind::Capture, opts, {}};
    }

    if (agg_cmd->parsed()) {
        if (opt_agg_agents->count() == 0 || agg_agents_val.empty()) {
            err << "Error: at least one --agent must be specified\n";
            return {ExitCode::UsageError, CommandKind::None, {}, {}};
        }

        for (const auto& agent : agg_agents_val) {
            if (!is_valid_agent_endpoint(agent)) {
                err << "Error: invalid agent endpoint format: " << agent << '\n';
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_interval->count() > 0) {
            if (!std::isfinite(agg_interval_val) || agg_interval_val <= 0.0) {
                err << "Error: --interval must be a finite positive number\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_syn->count() > 0) {
            if (!std::isfinite(agg_syn_thresh_val) || agg_syn_thresh_val <= 0.0) {
                err << "Error: --syn-threshold must be a finite positive number\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_pps->count() > 0) {
            if (!std::isfinite(agg_pps_thresh_val) || agg_pps_thresh_val <= 0.0) {
                err << "Error: --pps-threshold must be a finite positive number\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_syn_ack->count() > 0) {
            if (!std::isfinite(agg_syn_ack_ratio_val) || agg_syn_ack_ratio_val <= 0.0) {
                err << "Error: --syn-ack-ratio must be greater than 0.0\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_proto_share->count() > 0) {
            if (!std::isfinite(agg_proto_share_val) || agg_proto_share_val <= 0.0) {
                err << "Error: --proto-share must be greater than 0.0\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_port_share->count() > 0) {
            if (!std::isfinite(agg_port_share_val) || agg_port_share_val <= 0.0) {
                err << "Error: --port-share must be greater than 0.0\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        if (opt_agg_csv->count() > 0) {
            if (agg_csv_val.empty()) {
                err << "Error: --csv file path cannot be empty\n";
                return {ExitCode::UsageError, CommandKind::None, {}, {}};
            }
        }

        AggregateCliOptions opts;
        opts.agents = std::move(agg_agents_val);
        opts.api_token = agg_token_val;
        opts.interval_seconds = agg_interval_val;
        opts.timeout_ms = agg_timeout_ms_val;
        opts.rounds = static_cast<std::uint64_t>(agg_rounds_val);
        opts.min_agents = static_cast<std::size_t>(agg_min_agents_val);
        opts.syn_threshold = agg_syn_thresh_val;
        opts.pps_threshold = agg_pps_thresh_val;
        opts.syn_ack_ratio = agg_syn_ack_ratio_val;
        opts.proto_share = agg_proto_share_val;
        opts.port_share = agg_port_share_val;
        if (opt_agg_csv->count() > 0) {
            opts.csv_file = agg_csv_val;
        }
        opts.quiet = agg_quiet_val;

        return {ExitCode::Ok, CommandKind::Aggregate, {}, opts};
    }

    return {ExitCode::UsageError, CommandKind::None, {}, {}};
}

CliParseResult parse_cli(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    argv.push_back("netsight");
    for (const auto& a : args) {
        argv.push_back(a.c_str());
    }
    return parse_cli(static_cast<int>(argv.size()), argv.data(), out, err);
}

}