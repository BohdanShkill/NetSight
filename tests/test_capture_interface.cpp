#include <gtest/gtest.h>
#include "netsight/capture/ICaptureEngine.hpp"

class MockCaptureEngine : public netsight::ICaptureEngine
{
private:
    bool running_{false};
    std::string last_error_{};
    bool opened_{false};
public:
    bool start(netsight::PacketCallback callback) override{
        if (!opened_){
            last_error_ = "Engine not opened";
            return false;
        }
        const netsight::Byte dummy[1] = {0};
        callback(netsight::RawPacket{dummy, 1, 1});
        running_ = true;
        return true;
    }
    
    bool is_running() const override {
        return running_;
    }
    
    std::string get_last_error() const override {
        return last_error_;
    }

    void stop() override{
        running_ = false;
    }

    std::vector<netsight::NetworkInterface> list_interfaces() override{
        return std::vector<netsight::NetworkInterface>{};
    }

    bool open(const std::string& name,const netsight::CaptureConfig& config) override{
        if (should_fail_open){
            last_error_ = "Failed to open interface";
            return false;
        }
        opened_ = true;
        return true;
    }

    bool set_filter(const std::string& bpf_expression) override{
        return true; 
    }

    bool should_fail_open{false};
};

TEST(CaptureInterfaceTest, EngineLifecycle){
    MockCaptureEngine engine;
    bool packet_received = false;
    EXPECT_EQ(engine.is_running(), false);
    EXPECT_TRUE(engine.start([&packet_received](const netsight::RawPacket&){
        packet_received = true;
    }));
    EXPECT_EQ(packet_received, true);
    EXPECT_EQ(engine.is_running(), true);
    engine.stop();
    EXPECT_EQ(engine.is_running(), false);
}

TEST(CaptureInterfaceTest, CaptureConfig){
    netsight::CaptureConfig config;
    EXPECT_EQ(config.snapshot_lenght, 65535);
    EXPECT_EQ(config.primiscuous_mode, true);
    EXPECT_EQ(config.read_timeout_ms, 1000);
    EXPECT_EQ(config.bpf_filter, config.bpf_filter.empty());
}

TEST(CaptureInterfaceTest, ErrorHandling){
    MockCaptureEngine engine;
    engine.should_fail_open = true;
    netsight::CaptureConfig config;
    EXPECT_FALSE(engine.open("eth0", config));
    EXPECT_EQ(engine.get_last_error(), "Failed to open interface");
    
}

TEST(CaptureInterfaceTest, NetworkInterfaceStateRetention){
    netsight::NetworkInterface interface;
    interface.name = "eth0";
    interface.description = "Ethernet Interface";
    interface.ipv4_address = "192.168.1.1";
    interface.is_loopback = false;
    interface.up = true;

    EXPECT_EQ(interface.name, "eth0");
    EXPECT_EQ(interface.description, "Ethernet Interface");
    EXPECT_EQ(interface.ipv4_address, "192.168.1.1");
    EXPECT_FALSE(interface.is_loopback);
    EXPECT_TRUE(interface.up);
}

TEST(CaptureInterfaceTest, PolimorphicLifecycle){
    std::unique_ptr<netsight::ICaptureEngine> engine = std::make_unique<MockCaptureEngine>();
    const auto interfaces = engine -> list_interfaces();
    EXPECT_FALSE(interfaces.empty());
    netsight::CaptureConfig config;
    ASSERT_TRUE(engine->open(interfaces.front().name, config));
    bool packet_received = false;
    engine->start([&packet_received](const netsight::RawPacket&){
        packet_received = true;
    });
    EXPECT_TRUE(engine->is_running());
    EXPECT_TRUE(packet_received);
    engine->stop();
    EXPECT_FALSE(engine->is_running());

}

TEST(CaptureInterfaceTest, StartBeforeOpen){
    MockCaptureEngine engine;
    bool callback_called = false;
    EXPECT_FALSE(engine.start([&callback_called](const netsight::RawPacket&){
        callback_called = true;
     }));
    EXPECT_EQ(engine.get_last_error(), "Engine not opened");
    EXPECT_FALSE(callback_called);
    EXPECT_FALSE(engine.is_running());
}