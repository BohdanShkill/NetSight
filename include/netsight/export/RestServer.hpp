#pragma once

#include "netsight/analytics/StatsSnapshot.hpp"
#include "netsight/export/JsonSerializer.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace netsight {

using SnapshotProvider = std::function<std::shared_ptr<const StatsSnapshot>()>;

struct RestConfig {
    std::string host{"127.0.0.1"};
    std::uint16_t port{8080};
    std::string bearer_token{};
    std::string version{"0.1.0"};
    std::size_t max_limit{kDefaultMaxApiLimit};
    std::size_t worker_threads{2};
};

class RestServer {
public:
    explicit RestServer(RestConfig cfg, SnapshotProvider provider);
    ~RestServer() noexcept;

    RestServer(const RestServer&) = delete;
    RestServer& operator=(const RestServer&) = delete;
    RestServer(RestServer&&) = delete;
    RestServer& operator=(RestServer&&) = delete;

    [[nodiscard]] bool start(std::string& error_msg);
    void stop() noexcept;

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::uint16_t bound_port() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}