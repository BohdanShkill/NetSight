#include "netsight/export/RestServer.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace netsight;

TEST(RestServerTest, BindsEphemeralPortAndStopsIdempotently) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;

    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));
    EXPECT_TRUE(server.is_running());
    EXPECT_GT(server.bound_port(), 0);

    server.stop();
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.bound_port(), 0);

    server.stop();
    EXPECT_FALSE(server.is_running());
    EXPECT_EQ(server.bound_port(), 0);
}

TEST(RestServerTest, StartAndImmediateStopDoesNotHang) {
    for (int i = 0; i < 10; ++i) {
        RestConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 0;

        RestServer server(cfg, nullptr);
        std::string err;
        ASSERT_TRUE(server.start(err));
        server.stop();
        EXPECT_FALSE(server.is_running());
    }
}

TEST(RestServerTest, DestructorStopsRunningServer) {
    std::uint16_t port = 0;
    {
        RestConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 0;

        RestServer server(cfg, nullptr);
        std::string err;
        ASSERT_TRUE(server.start(err));
        port = server.bound_port();
        ASSERT_GT(port, 0);
    }

    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(std::chrono::seconds(1));
    cli.set_read_timeout(std::chrono::seconds(1));
    auto res = cli.Get("/api/v1/health");
    EXPECT_FALSE(res);
}

TEST(RestServerTest, PortAlreadyInUseFailsCleanly) {
    RestConfig cfg1;
    cfg1.host = "127.0.0.1";
    cfg1.port = 0;
    RestServer s1(cfg1, nullptr);
    std::string err1;
    ASSERT_TRUE(s1.start(err1));
    std::uint16_t port = s1.bound_port();
    ASSERT_GT(port, 0);

    RestConfig cfg2;
    cfg2.host = "127.0.0.1";
    cfg2.port = port;
    RestServer s2(cfg2, nullptr);
    std::string err2;
    EXPECT_FALSE(s2.start(err2));
    EXPECT_FALSE(err2.empty());

    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));
    auto res = cli.Get("/api/v1/health");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);

    s1.stop();
}

TEST(RestServerTest, InvalidHostFailsSynchronously) {
    RestConfig cfg;
    cfg.host = "";
    RestServer server(cfg, nullptr);
    std::string err;
    EXPECT_FALSE(server.start(err));
    EXPECT_FALSE(err.empty());
    EXPECT_FALSE(server.is_running());

    RestConfig cfg_bad;
    cfg_bad.host = "999.999.999.999";
    RestServer server_bad(cfg_bad, nullptr);
    std::string err_bad;
    EXPECT_FALSE(server_bad.start(err_bad));
    EXPECT_FALSE(err_bad.empty());
    EXPECT_FALSE(server_bad.is_running());
}

TEST(RestServerTest, AllFiveEndpointsReturn200JsonAndSecurityHeaders) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    const std::vector<std::string> paths = {
        "/api/v1/health",
        "/api/v1/stats",
        "/api/v1/top-talkers",
        "/api/v1/alerts",
        "/api/v1/drops"
    };

    for (const auto& path : paths) {
        auto res = cli.Get(path.c_str());
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
        EXPECT_NE(res->get_header_value("Content-Type").find("application/json"), std::string::npos);
        EXPECT_EQ(res->get_header_value("Cache-Control"), "no-store");
        EXPECT_EQ(res->get_header_value("X-Content-Type-Options"), "nosniff");
        EXPECT_FALSE(res->has_header("Access-Control-Allow-Origin"));

        EXPECT_NO_THROW({
            auto j = json::parse(res->body);
            EXPECT_TRUE(j.is_object());
        });
    }

    server.stop();
}

TEST(RestServerTest, BearerAuthBlocksProtectedEndpointsButAllowsHealth) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    cfg.bearer_token = "s3cr3t";
    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    auto res_health = cli.Get("/api/v1/health");
    ASSERT_TRUE(res_health);
    EXPECT_EQ(res_health->status, 200);

    const std::vector<std::string> paths = {
        "/api/v1/stats",
        "/api/v1/top-talkers",
        "/api/v1/alerts",
        "/api/v1/drops",
        "/api/v1/unknown"
    };

    for (const auto& path : paths) {
        auto res = cli.Get(path.c_str());
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 401);
        EXPECT_EQ(res->get_header_value("WWW-Authenticate"), "Bearer");
        auto j = json::parse(res->body);
        EXPECT_EQ(j["error"]["code"], "unauthorized");
    }

    httplib::Headers basic_hdr = {{"Authorization", "Basic s3cr3t"}};
    auto res_basic = cli.Get("/api/v1/stats", basic_hdr);
    ASSERT_TRUE(res_basic);
    EXPECT_EQ(res_basic->status, 401);

    httplib::Headers wrong_hdr = {{"Authorization", "Bearer wrong"}};
    auto res_wrong = cli.Get("/api/v1/stats", wrong_hdr);
    ASSERT_TRUE(res_wrong);
    EXPECT_EQ(res_wrong->status, 401);

    httplib::Headers extra_hdr = {{"Authorization", "Bearer s3cr3t_extra"}};
    auto res_extra = cli.Get("/api/v1/stats", extra_hdr);
    ASSERT_TRUE(res_extra);
    EXPECT_EQ(res_extra->status, 401);

    httplib::Headers dup_hdr;
    dup_hdr.emplace("Authorization", "Bearer s3cr3t");
    dup_hdr.emplace("Authorization", "Bearer s3cr3t");
    auto res_dup = cli.Get("/api/v1/stats", dup_hdr);
    ASSERT_TRUE(res_dup);
    EXPECT_EQ(res_dup->status, 401);

    server.stop();
}

TEST(RestServerTest, BearerAuthAcceptsCaseInsensitiveScheme) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    cfg.bearer_token = "s3cr3t";
    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    httplib::Headers lower_hdr = {{"Authorization", "bearer s3cr3t"}};
    auto res1 = cli.Get("/api/v1/stats", lower_hdr);
    ASSERT_TRUE(res1);
    EXPECT_EQ(res1->status, 200);

    httplib::Headers mixed_hdr = {{"Authorization", "Bearer s3cr3t"}};
    auto res2 = cli.Get("/api/v1/stats", mixed_hdr);
    ASSERT_TRUE(res2);
    EXPECT_EQ(res2->status, 200);

    server.stop();
}

TEST(RestServerTest, NonGetMethodsReturn405WithAllowHeader) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    auto post_res = cli.Post("/api/v1/stats", "{}", "application/json");
    ASSERT_TRUE(post_res);
    EXPECT_EQ(post_res->status, 405);
    EXPECT_EQ(post_res->get_header_value("Allow"), "GET");
    auto j_post = json::parse(post_res->body);
    EXPECT_EQ(j_post["error"]["code"], "method_not_allowed");

    auto put_res = cli.Put("/api/v1/stats", "{}", "application/json");
    ASSERT_TRUE(put_res);
    EXPECT_EQ(put_res->status, 405);
    EXPECT_EQ(put_res->get_header_value("Allow"), "GET");

    auto del_res = cli.Delete("/api/v1/stats");
    ASSERT_TRUE(del_res);
    EXPECT_EQ(del_res->status, 405);
    EXPECT_EQ(del_res->get_header_value("Allow"), "GET");

    auto health_post = cli.Post("/api/v1/health", "{}", "application/json");
    ASSERT_TRUE(health_post);
    EXPECT_EQ(health_post->status, 405);
    EXPECT_EQ(health_post->get_header_value("Allow"), "GET");

    server.stop();
}

TEST(RestServerTest, InvalidQueryParamsReturn400WithSpecificCode) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    const std::vector<std::string> bad_urls = {
        "/api/v1/top-talkers?limit=0",
        "/api/v1/top-talkers?limit=-3",
        "/api/v1/top-talkers?limit=abc",
        "/api/v1/top-talkers?limit=1001",
        "/api/v1/top-talkers?limit=1&limit=2",
        "/api/v1/alerts?state=bad",
        "/api/v1/alerts?state=active&state=resolved"
    };

    for (const auto& url : bad_urls) {
        auto res = cli.Get(url.c_str());
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 400);
        auto j = json::parse(res->body);
        EXPECT_EQ(j["error"]["code"], "invalid_query_param");
    }

    server.stop();
}

TEST(RestServerTest, ValidLimitAndStateFilterWorkOverHttp) {
    auto snap = std::make_shared<StatsSnapshot>();
    const std::uint8_t ip1[4] = {10, 0, 0, 1};
    const std::uint8_t ip2[4] = {10, 0, 0, 2};
    const std::uint8_t ip3[4] = {10, 0, 0, 3};
    snap->top_talkers = {
        TalkerEntry{IpAddress::from_ipv4(ip1), 10, 1000},
        TalkerEntry{IpAddress::from_ipv4(ip2), 8, 800},
        TalkerEntry{IpAddress::from_ipv4(ip3), 6, 600}
    };

    Alert a1{};
    a1.id = 1;
    a1.state = AlertState::Active;
    Alert a2{};
    a2.id = 2;
    a2.state = AlertState::Resolved;
    Alert a3{};
    a3.id = 3;
    a3.state = AlertState::Active;
    snap->alerts = {a1, a2, a3};

    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    RestServer server(cfg, [snap]() { return snap; });
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    auto res_talkers = cli.Get("/api/v1/top-talkers?limit=1");
    ASSERT_TRUE(res_talkers);
    EXPECT_EQ(res_talkers->status, 200);
    auto j_talkers = json::parse(res_talkers->body);
    EXPECT_EQ(j_talkers["count"], 1);
    EXPECT_EQ(j_talkers["total_available"], 3);
    EXPECT_EQ(j_talkers["talkers"].size(), 1);

    auto res_alerts = cli.Get("/api/v1/alerts?state=active&limit=1");
    ASSERT_TRUE(res_alerts);
    EXPECT_EQ(res_alerts->status, 200);
    auto j_alerts = json::parse(res_alerts->body);
    EXPECT_EQ(j_alerts["count"], 1);
    EXPECT_EQ(j_alerts["total_matching"], 2);
    EXPECT_EQ(j_alerts["alerts"].size(), 1);
    EXPECT_EQ(j_alerts["alerts"][0]["id"], 1);

    server.stop();
}

TEST(RestServerTest, UnknownRouteReturns404Json) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    RestServer server(cfg, nullptr);
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    auto res1 = cli.Get("/unknown");
    ASSERT_TRUE(res1);
    EXPECT_EQ(res1->status, 404);
    auto j1 = json::parse(res1->body);
    EXPECT_EQ(j1["error"]["code"], "not_found");

    auto res2 = cli.Get("/api/v1/unknown");
    ASSERT_TRUE(res2);
    EXPECT_EQ(res2->status, 404);
    auto j2 = json::parse(res2->body);
    EXPECT_EQ(j2["error"]["code"], "not_found");

    server.stop();
}

TEST(RestServerTest, NullSnapshotProviderFallsBackToEmptySnapshot) {
    RestConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 0;
    RestServer server(cfg, []() -> std::shared_ptr<const StatsSnapshot> {
        return nullptr;
    });
    std::string err;
    ASSERT_TRUE(server.start(err));

    httplib::Client cli("127.0.0.1", server.bound_port());
    cli.set_connection_timeout(std::chrono::seconds(2));
    cli.set_read_timeout(std::chrono::seconds(2));

    auto res = cli.Get("/api/v1/stats");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    auto j = json::parse(res->body);
    EXPECT_EQ(j["totals"]["packets"], 0);

    server.stop();
}