#include "Cli.hpp"

#include <CLI/CLI.hpp>

#include <cmath>
#include <limits>
#include <ostream>

#ifndef NETSIGHT_VERSION
#define NETSIGHT_VERSION "0.1.0"
#endif

namespace netsight {

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
    auto* opt_snaplen = cap_cmd->add_option("--snaplen", snaplen_val, "Snapshot length in bytes (64..262144)")
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

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        int rc = app.exit(e, out, err);
        if (rc != 0 && opt_bpf->count() > 0 && opt_file->count() > 0) {
            err << "Hint: --bpf is only supported for live capture (-i). For offline pcap (-r), use --filter-ip or --filter-port.\n";
        }
        return {rc == 0 ? ExitCode::Ok : ExitCode::UsageError, CommandKind::None, {}};
    }

    if (list_cmd->parsed()) {
        return {ExitCode::Ok, CommandKind::List, {}};
    }

    if (cap_cmd->parsed()) {
        CaptureCliOptions opts;

        if (opt_iface->count() > 0) {
            opts.interface_arg = interface_arg_val;
        }
        if (opt_file->count() > 0) {
            opts.read_file = read_file_val;
        }
        if (opt_bpf->count() > 0) {
            opts.bpf_filter = bpf_filter_val;
        }
        if (opt_snaplen->count() > 0) {
            opts.snaplen = static_cast<std::uint32_t>(snaplen_val);
        }
        if (no_promisc) {
            opts.promiscuous = false;
        }

        if (opt_f_ip->count() > 0) {
            auto parsed_ip = parse_ip_address(filter_ip_raw_val);
            if (!parsed_ip.has_value()) {
                err << "Error: invalid IP address for --filter-ip: " << filter_ip_raw_val << '\n';
                return {ExitCode::UsageError, CommandKind::None, {}};
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
                return {ExitCode::UsageError, CommandKind::None, {}};
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
                return {ExitCode::UsageError, CommandKind::None, {}};
            }
            opts.csv_prefix = csv_prefix_val;
        }

        if (opt_aport->count() > 0) {
            opts.api_port = static_cast<std::uint16_t>(api_port_val);
            if (api_host_val.empty()) {
                err << "Error: --api-host cannot be empty\n";
                return {ExitCode::UsageError, CommandKind::None, {}};
            }
            opts.api_host = api_host_val;
            opts.api_token = api_token_val;
        }

        opts.quiet = quiet_val;

        return {ExitCode::Ok, CommandKind::Capture, opts};
    }

    return {ExitCode::UsageError, CommandKind::None, {}};
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