#pragma once

#include <cstddef>                  
#include <cstdint>                  
#include "netsight/core/Types.hpp"  

namespace netsight {

    class ByteReader
    {
    private:
        const Byte* data_{nullptr};
        std::size_t size_{0};
        std::size_t pos_{0};
        bool failed_{false};

        bool can_read(std::size_t n) const noexcept {
            return !failed_ && (n <= (size_ - pos_));
        }

    public:
        ByteReader(const Byte* data, std::size_t size) noexcept
            : data_(data),
            size_(data != nullptr ? size : 0),
            pos_(0),
            failed_(false)
        {  
        }
        explicit ByteReader(const ByteBuffer& buffer) noexcept
            : ByteReader(buffer.data(), buffer.size()) {}
        
        
        bool ok() const noexcept {
            return !failed_;
        }
        std::size_t position() const noexcept {
            return pos_;
        }
        std::size_t remaining() const noexcept {
            return size_ - pos_;
        }

        std::uint8_t u8() noexcept {
            if(!can_read(1)){
                failed_ = true;
                return 0;
            }

            std:: uint8_t val = data_[pos_];
            pos_ += 1;
            return val;
        }
        std::uint16_t u16_be() noexcept {
            if (!can_read(2)) { failed_ = true; return 0; }
            auto val = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data_[pos_]) << 8) |
                                                   static_cast<std::uint16_t>(data_[pos_ + 1]));
            pos_ += 2;
            return val;
        }
        std::uint16_t u16_le() noexcept {
            if (!can_read(2)) { failed_ = true; return 0; }
            auto val = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[pos_]) |
                                                 (static_cast<std::uint16_t>(data_[pos_ + 1]) << 8));
            pos_ += 2;
            return val;
        }
        std::uint32_t u32_be() noexcept {
            if (!can_read(4)) { failed_ = true; return 0; }
            auto val = (static_cast<std::uint32_t>(data_[pos_]) << 24) |
                       (static_cast<std::uint32_t>(data_[pos_ + 1]) << 16) |
                       (static_cast<std::uint32_t>(data_[pos_ + 2]) << 8) |
                       static_cast<std::uint32_t>(data_[pos_ + 3]);
            pos_ += 4;
            return val;
        }
        std::uint32_t u32_le() noexcept {
            if (!can_read(4)) { failed_ = true; return 0; }
            auto val = (static_cast<std::uint32_t>(data_[pos_ + 3]) << 24) |
                       (static_cast<std::uint32_t>(data_[pos_ + 2]) << 16) |
                       (static_cast<std::uint32_t>(data_[pos_ + 1]) << 8) |
                       static_cast<std::uint32_t>(data_[pos_]);
            pos_ += 4;
            return val;
        }

        void skip(std::size_t n) noexcept {
            if (!can_read(n)) { failed_ = true; return; }
            pos_ += n;
        }
        const Byte* bytes(std::size_t n) noexcept {
            if (!can_read(n)) { failed_ = true; return nullptr; }
            const Byte* ptr = data_ + pos_;
            pos_ += n;
            return ptr;
        }
    };

}