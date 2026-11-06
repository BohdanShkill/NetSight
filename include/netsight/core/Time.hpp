#pragma once

#include <string>
#include "netsight/core/Types.hpp"

namespace netsight {

[[nodiscard]] std::string format_iso8601_utc(Timestamp ts);

}