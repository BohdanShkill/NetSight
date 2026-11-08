#include "netsight/core/Time.hpp"

#include <cstdint>
#include <cstdio>

namespace netsight {

namespace {

constexpr std::int64_t floor_div(std::int64_t a, std::int64_t b) noexcept {
    std::int64_t q = a / b;
    std::int64_t r = a % b;
    if (r < 0) {
        --q;
    }
    return q;
}

struct CivilDate {
    std::int64_t year;
    unsigned month;
    unsigned day;
};

CivilDate civil_from_days(std::int64_t z) noexcept {
    z += 719468;
    const std::int64_t era = floor_div(z, 146097);
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400 + (m <= 2 ? 1 : 0);
    return {y, m, d};
}

}

std::string format_iso8601_utc(Timestamp ts) {
    constexpr std::int64_t kDayUs = 86'400'000'000LL;
    const std::int64_t us = ts.count();

    const std::int64_t days = floor_div(us, kDayUs);
    std::int64_t rem = us % kDayUs;
    if (rem < 0) {
        rem += kDayUs;
    }
    
    const CivilDate cd = civil_from_days(days);

    const auto hh = static_cast<unsigned>(rem / 3'600'000'000LL);
    const auto mi = static_cast<unsigned>((rem / 60'000'000LL) % 60);
    const auto ss = static_cast<unsigned>((rem / 1'000'000LL) % 60);
    const auto us6 = static_cast<unsigned>(rem % 1'000'000LL);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02u:%02u:%02u.%06uZ",
                  static_cast<long long>(cd.year),
                  cd.month,
                  cd.day,
                  hh,
                  mi,
                  ss,
                  us6);

    return std::string(buf);
}

}