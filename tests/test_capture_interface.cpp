#include <gtest/gtest.h>
#include "netsight/capture/ICaptureEngine.hpp"

class MockCaptureEngine : public netsight::ICaptureEngine
{
private:
    bool running_{false};
    std::string last_error_{};
public:
    bool start(netsight::PacketCallback callback) override{
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
        return true;
    }

    bool set_filter(const std::string& bpf_expression) override{
        return true; 
    }
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

