#include <gtest/gtest.h>

#include "Signals.hpp"

#include <csignal>

using namespace netsight;

TEST(SignalsTest, InitialStateIsFalseAndManualRequestSetsTrue) {
    SignalGuard guard;
    EXPECT_FALSE(SignalGuard::stop_requested());

    SignalGuard::request_stop();
    EXPECT_TRUE(SignalGuard::stop_requested());

    SignalGuard::reset();
    EXPECT_FALSE(SignalGuard::stop_requested());
}

TEST(SignalsTest, RaiseSigintSetsStopRequestedWithoutCrashing) {
    SignalGuard guard;
    EXPECT_FALSE(SignalGuard::stop_requested());

    std::raise(SIGINT);
    EXPECT_TRUE(SignalGuard::stop_requested());
}

TEST(SignalsTest, GuardDestructorRestoresHandlersCleanly) {
    {
        SignalGuard guard1;
        EXPECT_FALSE(SignalGuard::stop_requested());
        SignalGuard::request_stop();
        EXPECT_TRUE(SignalGuard::stop_requested());
    }

    {
        SignalGuard guard2;
        EXPECT_FALSE(SignalGuard::stop_requested());
    }
}