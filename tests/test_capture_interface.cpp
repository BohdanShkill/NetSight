#include <gtest/gtest.h>
#include "netsight/capture/ICaptureEngine.hpp"

class MockCaptureEngine : public netsight::ICaptureEngine
{
private:
    bool running_{false};
    std::string last_error_{};
public:
    
    bool is_running() const override {
        return running_;
    }
    
    std::string get_last_error() const override {
        return last_error_;
    }

    void stop() override{
        running_ = false;
    }
};



