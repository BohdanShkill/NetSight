#pragma once

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

}