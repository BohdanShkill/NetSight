#pragma once

#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <utility>

namespace netsight::test {

class TempFile {
public:
    explicit TempFile(const std::string& prefix = "netsight_test_") {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<std::uint64_t> dis;

        path_ = std::filesystem::temp_directory_path() / 
                (prefix + std::to_string(dis(gen)) + ".pcap");
    }

    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    TempFile(TempFile&& other) noexcept : path_(std::move(other.path_)) {
        other.path_.clear();
    }

    TempFile& operator=(TempFile&& other) noexcept {
        if (this != &other) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
            path_ = std::move(other.path_);
            other.path_.clear();
        }
        return *this;
    }

    const std::filesystem::path& path() const noexcept { return path_; }
    std::string string() const { return path_.string(); }

private:
    std::filesystem::path path_;
};

}