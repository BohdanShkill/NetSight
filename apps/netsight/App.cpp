#include "App.hpp"

#include "netsight/analytics/DistributedAggregator.hpp"
#include "netsight/analytics/IntervalTracker.hpp"
#include "netsight/analytics/TrafficAnalyzer.hpp"
#include "netsight/capture/PcapLiveSource.hpp"
#include "netsight/core/Time.hpp"
#include "netsight/export/AgentPoller.hpp"
#include "netsight/export/CsvWriter.hpp"
#include "netsight/export/RestServer.hpp"
#include "netsight/pipeline/CaptureSession.hpp"
#include "netsight/source/PcapFileReader.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <locale>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifndef NETSIGHT_VERSION
#define NETSIGHT_VERSION "0.1.0"
#endif

namespace netsight {

namespace {

Timestamp current_utc_timestamp() noexcept {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<Timestamp>(now);
}

std::string_view trim_whitespace(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) {
        sv.remove_suffix(1);
    }
    return sv;
}

bool parse_exact_index(std::string_view sv, std::size_t& out_idx) noexcept {
    if (sv.empty()) {
        return false;
    }
    std::size_t val = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
    if (ec != std::errc{} || ptr != sv.data() + sv.size()) {
        return false;
    }
    out_idx = val;
    return true;
}

std::string format_interface_flags(const NetworkInterface& iface) {
    std::string flags;
    if (iface.is_loopback) {
        flags += "[loopback]";
    }
    if (iface.is_up) {
        flags += "[up]";
    } else {
        flags += "[down]";
    }
    return flags;
}

void print_interfaces_table(std::ostream& out, const std::vector<NetworkInterface>& ifaces) {
    out << "Interfaces found: " << ifaces.size() << '\n';
    for (std::size_t i = 0; i < ifaces.size(); ++i) {
        const auto& iface = ifaces[i];
        const std::string ip = iface.ipv4_address.empty() ? "-" : iface.ipv4_address;
        const std::string flags = format_interface_flags(iface);
        const std::string desc = iface.description.empty() ? "-" : iface.description;

        out << "  [" << i << "] " << iface.name
            << " | IPv4: " << ip
            << " | Flags: " << flags
            << " | Desc: " << desc << '\n';
    }
}

ExitCode run_list(AppEnv& env) {
    std::string err_msg;
    const auto ifaces = env.list_interfaces_fn ? env.list_interfaces_fn(err_msg) : list_interfaces(err_msg);
    if (!err_msg.empty()) {
        env.err << "Error listing network interfaces: " << err_msg << '\n';
        return ExitCode::RuntimeError;
    }
    if (ifaces.empty()) {
        env.out << "No network interfaces found.\n";
        return ExitCode::Ok;
    }
    print_interfaces_table(env.out, ifaces);
    return ExitCode::Ok;
}

struct ResolvedSource {
    ExitCode status{ExitCode::Ok};
    bool interrupted{false};
    std::unique_ptr<IPacketSource> source{};
    const PcapLiveSource* live_raw{nullptr};
    bool is_live{false};
    std::string label{};
};

ResolvedSource resolve_capture_source(const CaptureCliOptions& opts, AppEnv& env) {
    if (opts.read_file.has_value()) {
        std::string err_msg;
        auto reader = PcapFileReader::open(*opts.read_file, err_msg);
        if (!reader) {
            env.err << "Error opening pcap file '" << *opts.read_file << "': " << err_msg << '\n';
            return {ExitCode::RuntimeError, false, nullptr, nullptr, false, {}};
        }
        return {ExitCode::Ok, false, std::move(reader), nullptr, false, *opts.read_file};
    }

    std::string device_name;
    if (opts.interface_arg.has_value()) {
        const std::string& raw = *opts.interface_arg;
        if (raw.empty()) {
            env.err << "Error: --interface cannot be empty\n";
            return {ExitCode::UsageError, false, nullptr, nullptr, false, {}};
        }

        std::size_t idx = 0;
        if (parse_exact_index(raw, idx)) {
            std::string err_msg;
            const auto ifaces = env.list_interfaces_fn ? env.list_interfaces_fn(err_msg) : list_interfaces(err_msg);
            if (!err_msg.empty()) {
                env.err << "Error listing network interfaces: " << err_msg << '\n';
                return {ExitCode::RuntimeError, false, nullptr, nullptr, false, {}};
            }

            bool exact_match = false;
            for (const auto& iface : ifaces) {
                if (iface.name == raw) {
                    device_name = raw;
                    exact_match = true;
                    break;
                }
            }

            if (!exact_match) {
                if (idx < ifaces.size()) {
                    device_name = ifaces[idx].name;
                } else {
                    env.err << "Error: invalid interface ID " << idx << " (available: 0.."
                            << (ifaces.empty() ? 0 : ifaces.size() - 1) << ")\n";
                    return {ExitCode::UsageError, false, nullptr, nullptr, false, {}};
                }
            }
        } else {
            device_name = raw;
        }
    } else {
        if (!(env.stdin_is_tty && env.stdout_is_tty)) {
            env.err << "Error: either --interface (-i) or --read-file (-r) is required in non-interactive mode\n";
            return {ExitCode::UsageError, false, nullptr, nullptr, false, {}};
        }

        std::string err_msg;
        const auto ifaces = env.list_interfaces_fn ? env.list_interfaces_fn(err_msg) : list_interfaces(err_msg);
        if (!err_msg.empty()) {
            env.err << "Error listing network interfaces: " << err_msg << '\n';
            return {ExitCode::RuntimeError, false, nullptr, nullptr, false, {}};
        }
        if (ifaces.empty()) {
            env.err << "No network interfaces found.\n";
            return {ExitCode::RuntimeError, false, nullptr, nullptr, false, {}};
        }

        print_interfaces_table(env.out, ifaces);
        env.out << "Select interface ID [0.." << (ifaces.size() - 1) << "]: " << std::flush;

        std::string line;
        const bool got_line = static_cast<bool>(std::getline(env.in, line));
        if (env.stop_requested_fn && env.stop_requested_fn()) {
            return {ExitCode::Ok, true, nullptr, nullptr, false, {}};
        }
        if (!got_line) {
            env.err << "Error: failed to read interface selection\n";
            return {ExitCode::UsageError, false, nullptr, nullptr, false, {}};
        }

        const std::string_view trimmed = trim_whitespace(line);
        std::size_t idx = 0;
        if (!parse_exact_index(trimmed, idx) || idx >= ifaces.size()) {
            env.err << "Error: invalid interface selection '" << trimmed << "'\n";
            return {ExitCode::UsageError, false, nullptr, nullptr, false, {}};
        }
        device_name = ifaces[idx].name;
    }

    CaptureConfig cap_cfg{};
    cap_cfg.snapshot_length = opts.snaplen;
    cap_cfg.promiscuous_mode = opts.promiscuous;
    cap_cfg.read_timeout_ms = 250;
    cap_cfg.bpf_filter = opts.bpf_filter;

    if (env.open_live_source_fn) {
        std::string err_msg;
        auto custom_src = env.open_live_source_fn(device_name, cap_cfg, err_msg);
        if (!custom_src) {
            env.err << "Error opening interface '" << device_name << "': " << err_msg << '\n';
            return {ExitCode::RuntimeError, false, nullptr, nullptr, true, {}};
        }
        return {ExitCode::Ok, false, std::move(custom_src), nullptr, true, device_name};
    }

    std::string err_msg;
    auto live = PcapLiveSource::open(device_name, cap_cfg, err_msg);
    if (!live) {
        env.err << "Error opening interface '" << device_name << "': " << err_msg << '\n';
        return {ExitCode::RuntimeError, false, nullptr, nullptr, true, {}};
    }
    if (!live->last_error().empty()) {
        env.err << "WARNING: " << live->last_error() << '\n';
    }
    const PcapLiveSource* live_raw = live.get();
    return {ExitCode::Ok, false, std::move(live), live_raw, true, device_name};
}

bool is_loopback_host(std::string_view host) noexcept {
    return host == "127.0.0.1" || host == "::1" || host == "localhost";
}

std::size_t count_active_alerts(const StatsSnapshot& snap) noexcept {
    std::size_t active = 0;
    for (const auto& a : snap.alerts) {
        if (a.state == AlertState::Active) {
            ++active;
        }
    }
    return active;
}

std::string format_live_line(std::uint64_t elapsed_sec, const StatsSnapshot& snap) {
    std::ostringstream oss;
    oss.imbue(std::locale::classic());

    const std::uint64_t mins = elapsed_sec / 60;
    const std::uint64_t secs = elapsed_sec % 60;
    const double mib = static_cast<double>(snap.total_wire_bytes) / (1024.0 * 1024.0);
    const std::uint64_t total_drops =
        snap.drops.queue_dropped + snap.drops.kernel_dropped + snap.drops.interface_dropped;

    oss << '[' << std::setw(2) << std::setfill('0') << mins << ':'
        << std::setw(2) << std::setfill('0') << secs << "] "
        << "pkts: " << snap.total_packets
        << " (" << static_cast<std::uint64_t>(snap.packets_per_second) << " pps) | "
        << "wire: " << std::fixed << std::setprecision(2) << mib << " MiB | "
        << "drops: " << total_drops << " | "
        << "active alerts: " << count_active_alerts(snap);
    return oss.str();
}

void print_final_summary(std::ostream& out,
                         const StatsSnapshot& snap,
                         std::string_view mode_str,
                         std::string_view source_label,
                         std::string_view stop_tag,
                         const std::optional<std::string>& csv_prefix) {
    std::ostringstream oss;
    oss.imbue(std::locale::classic());

    const double mib = static_cast<double>(snap.total_wire_bytes) / (1024.0 * 1024.0);
    const std::uint64_t parse_errors =
        snap.status.truncated + snap.status.malformed + snap.status.unsupported_link;

    oss << "=== NetSight Capture Summary ===\n"
        << "Source:        " << source_label << " (" << mode_str << ")\n"
        << "Stop reason:   " << stop_tag << '\n'
        << "Packets:       " << snap.total_packets << '\n'
        << "Wire bytes:    " << snap.total_wire_bytes << " (" << std::fixed << std::setprecision(2) << mib << " MiB)\n"
        << "Duration:      " << std::fixed << std::setprecision(3) << snap.duration_seconds << " s ("
        << std::fixed << std::setprecision(1) << snap.packets_per_second << " pps)\n"
        << "L4 Breakdown:  TCP=" << snap.l4.tcp.packets
        << " UDP=" << snap.l4.udp.packets
        << " ICMP=" << (snap.l4.icmp.packets + snap.l4.icmpv6.packets)
        << " Other=" << (snap.l4.other.packets + snap.l4.none.packets) << '\n'
        << "Parse errors:  " << parse_errors
        << " (truncated=" << snap.status.truncated
        << ", malformed=" << snap.status.malformed
        << ", unsupported=" << snap.status.unsupported_link << ")\n"
        << "Drops:         filtered=" << snap.drops.filtered_out
        << " queue=" << snap.drops.queue_dropped
        << " kernel=" << snap.drops.kernel_dropped
        << " interface=" << snap.drops.interface_dropped << '\n'
        << "Alerts:        total=" << snap.alerts.size()
        << " active=" << count_active_alerts(snap) << '\n';

    for (const auto& alert : snap.alerts) {
        oss << "  - [" << to_string(alert.type) << "] [" << to_string(alert.state) << "] ";
        if (alert.type == AlertType::SynFlood) {
            oss << "dst=" << alert.dst_ip.to_string() << ':' << alert.dst_port
                << " peak_pps=" << std::fixed << std::setprecision(1) << alert.peak_rate_pps;
        } else {
            oss << "src=" << alert.src_ip.to_string()
                << " unique_ports=" << alert.unique_ports;
        }
        oss << '\n';
    }

    if (csv_prefix.has_value()) {
        oss << "CSV files:     " << *csv_prefix << "_timeseries.csv, "
            << *csv_prefix << "_summary.csv\n";
    }

    out << oss.str();
}

ExitCode run_capture(const CaptureCliOptions& opts, AppEnv& env) {
    auto resolved = resolve_capture_source(opts, env);
    if (resolved.interrupted) {
        return ExitCode::Ok;
    }
    if (resolved.status != ExitCode::Ok) {
        return resolved.status;
    }

    std::ofstream ts_file;
    std::ofstream summary_file;
    std::optional<TimeSeriesCsvWriter> ts_writer;

    if (opts.csv_prefix.has_value()) {
        const std::string ts_path = *opts.csv_prefix + "_timeseries.csv";
        const std::string sum_path = *opts.csv_prefix + "_summary.csv";

        ts_file.open(ts_path, std::ios::binary | std::ios::trunc);
        if (!ts_file.is_open()) {
            env.err << "Error: cannot open CSV file for writing: " << ts_path << '\n';
            return ExitCode::RuntimeError;
        }

        summary_file.open(sum_path, std::ios::binary | std::ios::trunc);
        if (!summary_file.is_open()) {
            env.err << "Error: cannot open CSV file for writing: " << sum_path << '\n';
            return ExitCode::RuntimeError;
        }

        ts_writer.emplace(ts_file);
        if (!ts_writer->ok()) {
            env.err << "Error: failed to write CSV header to: " << ts_path << '\n';
            return ExitCode::RuntimeError;
        }
    }

    TrafficAnalyzer analyzer{};
    analyzer.on_tick(Timestamp{0}, DropCounters{});

    std::optional<RestServer> rest;
    if (opts.api_port.has_value()) {
        if (!is_loopback_host(opts.api_host) && opts.api_token.empty()) {
            env.err << "WARNING: REST API is bound to non-loopback address (" << opts.api_host
                    << ") without --api-token authentication!\n";
        }

        RestConfig rcfg{};
        rcfg.host = opts.api_host;
        rcfg.port = *opts.api_port;
        rcfg.bearer_token = opts.api_token;
        rcfg.version = NETSIGHT_VERSION;

        rest.emplace(std::move(rcfg), [&analyzer]() {
            return analyzer.latest_snapshot();
        });

        std::string rest_err;
        if (!rest->start(rest_err)) {
            env.err << "Error starting REST server: " << rest_err << '\n';
            return ExitCode::RuntimeError;
        }

        if (env.on_api_listening) {
            env.on_api_listening(rest->bound_port());
        }

        if (!opts.quiet) {
            env.out << "REST API listening on http://" << opts.api_host << ':' << rest->bound_port() << '\n';
        }
    }

    CaptureSession* session_ptr = nullptr;
    std::atomic<bool> count_limit_reached{false};
    std::atomic<std::uint64_t> frozen_filtered_out{0};
    std::uint64_t accepted_packets = 0;

    auto collect_drops = [&]() noexcept -> DropCounters {
        DropCounters d{};
        if (session_ptr != nullptr) {
            const auto c = session_ptr->counters();
            if (count_limit_reached.load(std::memory_order_acquire)) {
                d.filtered_out = frozen_filtered_out.load(std::memory_order_relaxed);
            } else {
                d.filtered_out = (c.processed >= c.delivered) ? (c.processed - c.delivered) : 0;
            }
            d.queue_dropped = c.dropped;
        }
        if (resolved.live_raw != nullptr) {
            const auto st = resolved.live_raw->stats();
            d.kernel_dropped = st.kernel_dropped;
            d.interface_dropped = st.interface_dropped;
        }
        return d;
    };

    SessionConfig session_cfg{};
    session_cfg.queue_capacity = opts.queue_size;
    session_cfg.overflow = resolved.is_live ? OverflowPolicy::DropNewest : OverflowPolicy::Block;
    session_cfg.filter.ip = opts.filter_ip;
    session_cfg.filter.port = opts.filter_port;
    session_cfg.tick_interval = std::chrono::milliseconds(500);
    session_cfg.on_tick = [&]() {
        const Timestamp now_ts = resolved.is_live ? current_utc_timestamp() : Timestamp{0};
        analyzer.on_tick(now_ts, collect_drops());
    };

    auto sink = [&](const ParsedPacket& pkt) {
        if (opts.max_packets.has_value() && accepted_packets >= *opts.max_packets) {
            return;
        }
        if (ts_writer.has_value() && ts_writer->starts_new_interval(pkt.timestamp)) {
            auto snap = analyzer.on_tick(Timestamp{0}, collect_drops());
            if (snap) {
                ts_writer->write_row(*snap);
            }
        }
        analyzer.record(pkt);
        ++accepted_packets;
        if (opts.max_packets.has_value() && accepted_packets >= *opts.max_packets) {
            if (session_ptr != nullptr) {
                const auto c = session_ptr->counters();
                const std::uint64_t cur_delivered = c.delivered + 1;
                const std::uint64_t filt = (c.processed >= cur_delivered) ? (c.processed - cur_delivered) : 0;
                frozen_filtered_out.store(filt, std::memory_order_relaxed);
            }
            count_limit_reached.store(true, std::memory_order_release);
            if (session_ptr != nullptr) {
                session_ptr->stop();
            }
        }
    };

    CaptureSession session(std::move(resolved.source), std::move(session_cfg), std::move(sink));
    session_ptr = &session;

    if (!session.start()) {
        env.err << "Error starting capture session: " << session.last_error() << '\n';
        if (rest.has_value()) {
            rest->stop();
        }
        return ExitCode::RuntimeError;
    }

    const auto start_tp = std::chrono::steady_clock::now();
    auto last_tty_print = start_tp;
    std::size_t max_tty_len = 0;
    std::string stop_tag = "eof";

    while (!session.wait_for(std::chrono::milliseconds(50))) {
        if (env.stop_requested_fn && env.stop_requested_fn()) {
            stop_tag = "signal";
            break;
        }
        if (count_limit_reached.load(std::memory_order_acquire)) {
            stop_tag = "count";
            break;
        }
        const auto now_tp = std::chrono::steady_clock::now();
        if (opts.duration_seconds.has_value()) {
            const double elapsed_s = std::chrono::duration<double>(now_tp - start_tp).count();
            if (elapsed_s >= *opts.duration_seconds) {
                stop_tag = "duration";
                break;
            }
        }
        if (!opts.quiet && env.stdout_is_tty &&
            (now_tp - last_tty_print) >= std::chrono::milliseconds(500)) {
            last_tty_print = now_tp;
            auto snap = analyzer.latest_snapshot();
            if (snap) {
                const auto elapsed_sec = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(now_tp - start_tp).count());
                std::string line = format_live_line(elapsed_sec, *snap);
                if (line.size() < max_tty_len) {
                    line.append(max_tty_len - line.size(), ' ');
                } else {
                    max_tty_len = line.size();
                }
                env.out << '\r' << line << std::flush;
            }
        }
    }

    if (stop_tag == "eof") {
        if (count_limit_reached.load(std::memory_order_acquire)) {
            stop_tag = "count";
        } else if (env.stop_requested_fn && env.stop_requested_fn()) {
            stop_tag = "signal";
        }
    }

    session.stop();

    if (max_tty_len > 0) {
        env.out << '\r' << std::string(max_tty_len, ' ') << '\r' << std::flush;
    }

    const StopReason reason = session.stop_reason();
    if (reason == StopReason::Error) {
        stop_tag = "error";
    }

    const Timestamp final_ts = resolved.is_live ? current_utc_timestamp() : Timestamp{0};
    auto final_snap = analyzer.on_tick(final_ts, collect_drops());

    bool csv_ok = true;
    if (ts_writer.has_value() && final_snap) {
        ts_writer->write_row(*final_snap);
        ts_file.flush();

        const CsvMeta meta{
            {"version", NETSIGHT_VERSION},
            {"mode", resolved.is_live ? "live" : "file"},
            {"source", resolved.label},
            {"bpf", opts.bpf_filter},
            {"filter_ip", opts.filter_ip_raw},
            {"filter_port", opts.filter_port.has_value() ? std::to_string(*opts.filter_port) : ""},
            {"stop_reason", stop_tag}};

        write_summary_csv(summary_file, *final_snap, meta);
        summary_file.flush();

        csv_ok = ts_writer->ok() && !ts_file.fail() && !summary_file.fail();
        if (!csv_ok) {
            env.err << "Error: failed while flushing CSV output files\n";
        }
    }

    if (rest.has_value()) {
        rest->stop();
    }

    if (!opts.quiet && final_snap) {
        print_final_summary(env.out,
                            *final_snap,
                            resolved.is_live ? "live" : "file",
                            resolved.label,
                            stop_tag,
                            opts.csv_prefix);
    }

    if (reason == StopReason::Error) {
        env.err << "Capture error: " << session.last_error() << '\n';
        return ExitCode::RuntimeError;
    }
    if (!csv_ok) {
        return ExitCode::RuntimeError;
    }

    return ExitCode::Ok;
}

ExitCode run_aggregate(const AggregateCliOptions& opts, AppEnv& env) {
    DistributedAggregatorConfig agg_cfg{};
    agg_cfg.min_agents = opts.min_agents;
    agg_cfg.global_syn_pps_threshold = opts.syn_threshold;
    agg_cfg.global_volumetric_pps_threshold = opts.pps_threshold;

    DistributedAggregator aggregator{agg_cfg};
    IntervalTracker tracker{opts.agents.size()};

    AgentPollerConfig poller_cfg{};
    poller_cfg.timeout_ms = opts.timeout_ms;
    poller_cfg.api_token = opts.api_token;

    AgentPoller poller{poller_cfg};

    const std::size_t k = opts.agents.size();
    const std::size_t c = poller.config().max_parallel == 0 ? 1 : poller.config().max_parallel;
    const std::uint64_t waves = (k == 0) ? 0 : ((k + c - 1) / c);
    const std::uint64_t worst_ms = waves * 2ULL * static_cast<std::uint64_t>(opts.timeout_ms);
    const double interval_ms = opts.interval_seconds * 1000.0;

    if (static_cast<double>(worst_ms) > interval_ms) {
        env.err << "Warning: worst-case round duration (" << worst_ms << " ms) exceeds poll interval ("
                << static_cast<std::uint64_t>(interval_ms) << " ms)\n";
    }

    std::ofstream csv_file;
    if (opts.csv_file.has_value()) {
        csv_file.open(*opts.csv_file, std::ios::out | std::ios::trunc);
        if (!csv_file.is_open()) {
            env.err << "Error: failed to open CSV output file: " << *opts.csv_file << '\n';
            return ExitCode::RuntimeError;
        }
        csv_file << "round,online_agents,total_agents,total_packets,total_wire_bytes,global_pps,global_bps,tcp_packets,udp_packets,icmp_packets,other_packets,active_alerts,interval_packets,interval_agents\n";
        csv_file.flush();
    }

    if (!opts.quiet) {
        env.out << "Starting distributed metric aggregation (" << opts.agents.size() << " agents configured)\n";
    }

    std::uint64_t current_round = 0;
    std::uint64_t total_online_across_rounds = 0;
    GlobalNetworkSnapshot last_snapshot{};

    while (!env.stop_requested_fn || !env.stop_requested_fn()) {
        if (opts.rounds > 0 && current_round >= opts.rounds) {
            break;
        }

        ++current_round;
        auto reports = poller.poll_all(opts.agents);
        tracker.annotate(reports);
        last_snapshot = aggregator.aggregate(reports);
        total_online_across_rounds += last_snapshot.online_agents;

        if (csv_file.is_open()) {
            csv_file << current_round << ','
                     << last_snapshot.online_agents << ','
                     << last_snapshot.total_agents << ','
                     << last_snapshot.total_packets << ','
                     << last_snapshot.total_wire_bytes << ','
                     << std::fixed << std::setprecision(2) << last_snapshot.global_pps << ','
                     << std::fixed << std::setprecision(2) << last_snapshot.global_bps << ','
                     << last_snapshot.tcp_packets << ','
                     << last_snapshot.udp_packets << ','
                     << last_snapshot.icmp_packets << ','
                     << last_snapshot.other_packets << ','
                     << last_snapshot.alerts.size() << ','
                     << last_snapshot.interval_packets << ','
                     << last_snapshot.interval_agents << '\n';
            csv_file.flush();
        }

        if (!opts.quiet) {
            env.out << "Round " << current_round << ": Online agents: "
                    << last_snapshot.online_agents << "/" << last_snapshot.total_agents
                    << " | Packets: " << last_snapshot.total_packets
                    << " | PPS: " << std::fixed << std::setprecision(1) << last_snapshot.global_pps
                    << " | BPS: " << std::fixed << std::setprecision(1) << last_snapshot.global_bps
                    << " | Alerts: " << last_snapshot.alerts.size() << '\n';

            for (const auto& alert : last_snapshot.alerts) {
                std::string alert_type_name;
                switch (alert.type) {
                    case DistributedAlertType::DistributedSynFlood:
                        alert_type_name = "DistributedSynFlood";
                        break;
                    case DistributedAlertType::DistributedVolumetricFlood:
                        alert_type_name = "DistributedVolumetricFlood";
                        break;
                    case DistributedAlertType::DistributedTargetConcentration:
                        alert_type_name = "DistributedTargetConcentration";
                        break;
                }
                env.out << "[ALERT] " << alert_type_name << " (" << to_string(alert.type) << ") ["
                        << to_string(alert.severity) << "]: " << alert.description << '\n';
            }
        }

        if (opts.rounds > 0 && current_round >= opts.rounds) {
            break;
        }

        const auto sleep_total = std::chrono::duration<double>(opts.interval_seconds);
        const auto sleep_slice = std::chrono::milliseconds(50);
        auto elapsed = std::chrono::duration<double>::zero();
        while (elapsed < sleep_total) {
            if (env.stop_requested_fn && env.stop_requested_fn()) {
                break;
            }
            const auto step = std::min(std::chrono::duration_cast<std::chrono::duration<double>>(sleep_slice), sleep_total - elapsed);
            std::this_thread::sleep_for(step);
            elapsed += step;
        }
    }

    if (!opts.quiet) {
        env.out << "\n--- Distributed Aggregation Summary ---\n"
                << "Total rounds completed: " << current_round << '\n'
                << "Agents configured: " << opts.agents.size() << '\n'
                << "Online agents (last round): " << last_snapshot.online_agents << "/" << last_snapshot.total_agents << '\n'
                << "Total aggregated packets: " << last_snapshot.total_packets << '\n'
                << "Total aggregated bytes: " << last_snapshot.total_wire_bytes << '\n'
                << "Active distributed alerts: " << last_snapshot.alerts.size() << '\n';
    }

    if (total_online_across_rounds == 0) {
        env.err << "Error: all agents were unreachable across all rounds\n";
        return ExitCode::RuntimeError;
    }

    return ExitCode::Ok;
}

}

ExitCode run_netsight(int argc, const char* const* argv, AppEnv& env) {
    const CliParseResult parsed = parse_cli(argc, argv, env.out, env.err);
    if (parsed.exit_code != ExitCode::Ok || parsed.command == CommandKind::None) {
        return parsed.exit_code;
    }

    if (parsed.command == CommandKind::List) {
        return run_list(env);
    }

    if (parsed.command == CommandKind::Capture) {
        return run_capture(parsed.capture, env);
    }

    if (parsed.command == CommandKind::Aggregate) {
        return run_aggregate(parsed.aggregate, env);
    }

    return ExitCode::UsageError;
}

ExitCode run_netsight(const std::vector<std::string>& args, AppEnv& env) {
    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    argv.push_back("netsight");
    for (const auto& a : args) {
        argv.push_back(a.c_str());
    }
    return run_netsight(static_cast<int>(argv.size()), argv.data(), env);
}

}