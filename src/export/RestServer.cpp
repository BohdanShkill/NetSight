#include "netsight/export/RestServer.hpp"
#include "netsight/export/JsonSerializer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <httplib.h>

namespace netsight {

namespace {

std::optional<std::string_view> extract_bearer_token(std::string_view auth_header) noexcept {
    if (auth_header.size() <= 7) {
        return std::nullopt;
    }
    std::string_view prefix = auth_header.substr(0, 7);
    auto to_lower = [](char c) noexcept -> char {
        if (c >= 'A' && c <= 'Z') return static_cast<char>(c + ('a' - 'A'));
        return c;
    };
    const char* expected = "bearer ";
    for (std::size_t i = 0; i < 7; ++i) {
        if (to_lower(prefix[i]) != expected[i]) {
            return std::nullopt;
        }
    }
    return auth_header.substr(7);
}

bool constant_time_equals(std::string_view provided, std::string_view secret) noexcept {
    std::size_t diff = provided.size() ^ secret.size();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        unsigned char p = (i < provided.size()) ? static_cast<unsigned char>(provided[i]) : 0;
        unsigned char s = static_cast<unsigned char>(secret[i]);
        diff |= (p ^ s);
    }
    return diff == 0;
}

void respond_json(httplib::Response& res, int status, const std::string& body) {
    res.status = status;
    res.set_content(body, "application/json; charset=utf-8");
}

}

struct RestServer::Impl {
    RestConfig cfg_;
    SnapshotProvider provider_;

    mutable std::mutex lifecycle_mutex_{};
    std::unique_ptr<httplib::Server> server_{};
    std::thread thread_{};
    std::atomic<std::uint16_t> bound_port_{0};
    std::atomic<bool> running_{false};

    Impl(RestConfig cfg, SnapshotProvider provider)
        : cfg_(std::move(cfg)),
          provider_(std::move(provider)) {}

    ~Impl() noexcept {
        stop();
    }

    std::shared_ptr<const StatsSnapshot> current_snapshot() const {
        if (provider_) {
            auto snap = provider_();
            if (snap) {
                return snap;
            }
        }
        static const auto empty_snap = std::make_shared<const StatsSnapshot>();
        return empty_snap;
    }

    bool extract_optional_limit(const httplib::Request& req, httplib::Response& res, std::optional<std::size_t>& out_limit) const {
        std::size_t count = req.get_param_value_count("limit");
        if (count == 0) {
            out_limit = std::nullopt;
            return true;
        }
        if (count > 1) {
            respond_json(res, 400, serialize_error_json("invalid_query_param", "Duplicate query parameter 'limit'"));
            return false;
        }
        auto parsed = parse_limit_param(req.get_param_value("limit"), cfg_.max_limit);
        if (!parsed.has_value()) {
            respond_json(res, 400, serialize_error_json("invalid_query_param", "Query parameter 'limit' must be an integer between 1 and " + std::to_string(cfg_.max_limit)));
            return false;
        }
        out_limit = parsed;
        return true;
    }

    void setup_routes(httplib::Server& srv) {
        srv.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            if (req.method != "GET") {
                res.set_header("Allow", "GET");
                respond_json(res, 405, serialize_error_json("method_not_allowed", "Only GET requests are supported"));
                return httplib::Server::HandlerResponse::Handled;
            }

            if (!cfg_.bearer_token.empty() && req.path != "/api/v1/health") {
                if (req.get_header_value_count("Authorization") != 1) {
                    res.set_header("WWW-Authenticate", "Bearer");
                    respond_json(res, 401, serialize_error_json("unauthorized", "Missing or invalid Bearer token"));
                    return httplib::Server::HandlerResponse::Handled;
                }

                auto token = extract_bearer_token(req.get_header_value("Authorization"));
                if (!token.has_value() || !constant_time_equals(*token, cfg_.bearer_token)) {
                    res.set_header("WWW-Authenticate", "Bearer");
                    respond_json(res, 401, serialize_error_json("unauthorized", "Missing or invalid Bearer token"));
                    return httplib::Server::HandlerResponse::Handled;
                }
            }

            return httplib::Server::HandlerResponse::Unhandled;
        });

        srv.Get("/api/v1/health", [this](const httplib::Request&, httplib::Response& res) {
            auto snap = current_snapshot();
            respond_json(res, 200, serialize_health_json(cfg_.version, snap->snapshot_seq));
        });

        srv.Get("/api/v1/stats", [this](const httplib::Request&, httplib::Response& res) {
            auto snap = current_snapshot();
            respond_json(res, 200, serialize_stats_json(*snap));
        });

        srv.Get("/api/v1/top-talkers", [this](const httplib::Request& req, httplib::Response& res) {
            std::optional<std::size_t> limit;
            if (!extract_optional_limit(req, res, limit)) {
                return;
            }
            auto snap = current_snapshot();
            respond_json(res, 200, serialize_top_talkers_json(*snap, limit));
        });

        srv.Get("/api/v1/alerts", [this](const httplib::Request& req, httplib::Response& res) {
            std::optional<std::size_t> limit;
            if (!extract_optional_limit(req, res, limit)) {
                return;
            }

            AlertFilterState state_filter = AlertFilterState::All;
            std::size_t state_count = req.get_param_value_count("state");
            if (state_count > 1) {
                respond_json(res, 400, serialize_error_json("invalid_query_param", "Duplicate query parameter 'state'"));
                return;
            }
            if (state_count == 1) {
                auto parsed = parse_alert_state_param(req.get_param_value("state"));
                if (!parsed.has_value()) {
                    respond_json(res, 400, serialize_error_json("invalid_query_param", "Query parameter 'state' must be 'all', 'active', or 'resolved'"));
                    return;
                }
                state_filter = *parsed;
            }

            auto snap = current_snapshot();
            respond_json(res, 200, serialize_alerts_json(*snap, state_filter, limit));
        });

        srv.Get("/api/v1/drops", [this](const httplib::Request&, httplib::Response& res) {
            auto snap = current_snapshot();
            respond_json(res, 200, serialize_drops_json(*snap));
        });

        srv.set_error_handler([](const httplib::Request&, httplib::Response& res) {
            if (!res.body.empty()) {
                return;
            }
            if (res.status == 404) {
                respond_json(res, 404, serialize_error_json("not_found", "Endpoint not found"));
            } else if (res.status == 413 || res.status == 414 || res.status == 431) {
                respond_json(res, res.status, serialize_error_json("request_too_large", "Request exceeds size limits"));
            } else if (res.status >= 500) {
                respond_json(res, res.status, serialize_error_json("internal_error", "Internal server error"));
            } else {
                respond_json(res, res.status, serialize_error_json("bad_request", "Malformed HTTP request"));
            }
        });

        srv.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr) {
            respond_json(res, 500, serialize_error_json("internal_error", "Internal server error"));
        });
    }

    bool start(std::string& error_msg) {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (running_) {
            error_msg = "REST server is already running";
            return false;
        }
        if (cfg_.host.empty()) {
            error_msg = "REST bind host must not be empty";
            return false;
        }

        auto srv = std::make_unique<httplib::Server>();

        std::size_t threads = std::clamp(cfg_.worker_threads, std::size_t{1}, std::size_t{8});
        srv->new_task_queue = [threads] { return new httplib::ThreadPool(threads); };

        srv->set_read_timeout(5, 0);
        srv->set_write_timeout(5, 0);
        srv->set_keep_alive_timeout(5);
        srv->set_keep_alive_max_count(16);
        srv->set_payload_max_length(4096);
        srv->set_default_headers({
            {"Cache-Control", "no-store"},
            {"X-Content-Type-Options", "nosniff"}
        });

#ifdef _WIN32
        srv->set_socket_options([](socket_t sock) {
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&opt), sizeof(opt));
        });
#else
        srv->set_socket_options([](socket_t sock) {
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const void*>(&opt), sizeof(opt));
        });
#endif

        setup_routes(*srv);

        int actual_port = -1;
        if (cfg_.port == 0) {
            actual_port = srv->bind_to_any_port(cfg_.host);
        } else {
            if (srv->bind_to_port(cfg_.host, static_cast<int>(cfg_.port))) {
                actual_port = static_cast<int>(cfg_.port);
            }
        }

        if (actual_port <= 0) {
            error_msg = "Failed to bind REST server to " + cfg_.host + ":" + std::to_string(cfg_.port);
            return false;
        }

        server_ = std::move(srv);
        bound_port_ = static_cast<std::uint16_t>(actual_port);
        running_ = true;

        auto* raw_srv = server_.get();
        thread_ = std::thread([this, raw_srv]() {
            raw_srv->listen_after_bind();
            running_ = false;
        });

        raw_srv->wait_until_ready();

        if (!raw_srv->is_running() && !running_) {
            if (thread_.joinable()) {
                thread_.join();
            }
            bound_port_ = 0;
            server_.reset();
            error_msg = "REST server failed to enter listen loop";
            return false;
        }

        error_msg.clear();
        return true;
    }

    void stop() noexcept {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (server_) {
            server_->stop();
        }
        if (thread_.joinable()) {
            thread_.join();
        }
        running_ = false;
        bound_port_ = 0;
        server_.reset();
    }
};

RestServer::RestServer(RestConfig cfg, SnapshotProvider provider)
    : impl_(std::make_unique<Impl>(std::move(cfg), std::move(provider))) {}

RestServer::~RestServer() noexcept = default;

bool RestServer::start(std::string& error_msg) {
    return impl_->start(error_msg);
}

void RestServer::stop() noexcept {
    impl_->stop();
}

bool RestServer::is_running() const noexcept {
    return impl_->running_.load();
}

std::uint16_t RestServer::bound_port() const noexcept {
    return impl_->bound_port_.load();
}

}