#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/core/Types.hpp"

namespace netsight {

[[nodiscard]] std::string csv_escape(std::string_view field);

using CsvMeta = std::vector<std::pair<std::string, std::string>>;

void write_summary_csv(std::ostream& out, const StatsSnapshot& snap, const CsvMeta& meta = {});

class TimeSeriesCsvWriter {
public:
    explicit TimeSeriesCsvWriter(std::ostream& out, Timestamp interval = Timestamp{1'000'000});

    TimeSeriesCsvWriter(const TimeSeriesCsvWriter&) = delete;
    TimeSeriesCsvWriter& operator=(const TimeSeriesCsvWriter&) = delete;

    [[nodiscard]] bool starts_new_interval(Timestamp pkt_ts) noexcept;
    void write_row(const StatsSnapshot& snap);

    [[nodiscard]] std::size_t rows_written() const noexcept;
    [[nodiscard]] bool ok() const;

private:
    struct Totals {
        std::uint64_t packets{0};
        std::uint64_t wire_bytes{0};
        std::uint64_t tcp_packets{0};
        std::uint64_t udp_packets{0};
        std::uint64_t icmp_packets{0};
        std::uint64_t parse_errors{0};
        std::uint64_t dropped{0};
    };

    std::ostream& out_;
    Timestamp interval_;
    Timestamp row_start_{0};
    Timestamp next_start_{0};
    Totals prev_{};
    std::size_t rows_{0};
};

}