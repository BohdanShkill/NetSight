#pragma once

#include <chrono>
#include <future>
#include <string>
#include <utility>
#include <vector>

#include "netsight/core/Types.hpp"
#include "netsight/source/PcapFileReader.hpp"

namespace netsight::test {

struct ReadResult {
    std::vector<RawPacket> packets;
    StopReason reason{StopReason::Error};
    std::string error;
};

inline ReadResult read_all(PcapFileReader& reader) {
    using namespace std::chrono_literals;
    ReadResult res;
    std::promise<StopReason> prom;
    auto fut = prom.get_future();

    reader.start(
        [&res](RawPacket pkt) {
            res.packets.push_back(std::move(pkt));
        },
        [&prom](StopReason r) {
            prom.set_value(r);
        });

    if (fut.wait_for(5s) == std::future_status::ready) {
        res.reason = fut.get();
    }
    res.error = reader.last_error();
    return res;
}

}