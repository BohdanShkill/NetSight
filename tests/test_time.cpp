#include <gtest/gtest.h>
#include <limits>
#include "netsight/core/Time.hpp"

using netsight::Timestamp;
using netsight::format_iso8601_utc;

TEST(TimeTest, EpochZero) {
    EXPECT_EQ(format_iso8601_utc(Timestamp{0}), "1970-01-01T00:00:00.000000Z");
}

TEST(TimeTest, LeapDay2000) {
    EXPECT_EQ(format_iso8601_utc(Timestamp{951'782'400'000'000LL}), "2000-02-29T00:00:00.000000Z");
}

TEST(TimeTest, MicrosecondsPreserved) {
    EXPECT_EQ(format_iso8601_utc(Timestamp{1'700'000'000'123'456LL}), "2023-11-14T22:13:20.123456Z");
}

TEST(TimeTest, Year2038IsNotA32BitProblem) {
    EXPECT_EQ(format_iso8601_utc(Timestamp{2'147'483'648'000'000LL}), "2038-01-19T03:14:08.000000Z");
}

TEST(TimeTest, Year2100IsNotLeap) {
    EXPECT_EQ(format_iso8601_utc(Timestamp{4'107'456'000'000'000LL}), "2100-02-28T00:00:00.000000Z");
    EXPECT_EQ(format_iso8601_utc(Timestamp{4'107'542'400'000'000LL}), "2100-03-01T00:00:00.000000Z");
}

TEST(TimeTest, NegativeRoundsTowardMinusInfinity) {
    EXPECT_EQ(format_iso8601_utc(Timestamp{-1}), "1969-12-31T23:59:59.999999Z");
}

TEST(TimeTest, ExtremesDoNotCrash) {
    const auto min_str = format_iso8601_utc(Timestamp{std::numeric_limits<std::int64_t>::min()});
    EXPECT_FALSE(min_str.empty());
    EXPECT_EQ(min_str.back(), 'Z');

    const auto max_str = format_iso8601_utc(Timestamp{std::numeric_limits<std::int64_t>::max()});
    EXPECT_FALSE(max_str.empty());
    EXPECT_EQ(max_str.back(), 'Z');
}