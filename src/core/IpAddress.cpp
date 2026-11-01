#include "netsight/core/IpAddress.hpp"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <cstring>
#include <iomanip>
#include <sstream>

namespace netsight {

IpAddress IpAddress::from_ipv4(const std::uint8_t* raw4) noexcept {
    if (!raw4) {
        return IpAddress{};
    }
    IpAddress addr{};
    addr.protocol = NetworkProtocol::IPv4;
    std::memcpy(addr.bytes.data(), raw4, 4);
    return addr;
}

IpAddress IpAddress::from_ipv6(const std::uint8_t* raw16) noexcept {
    if (!raw16) {
        return IpAddress{};
    }
    IpAddress addr{};
    addr.protocol = NetworkProtocol::IPv6;
    std::memcpy(addr.bytes.data(), raw16, 16);
    return addr;
}

bool IpAddress::operator==(const IpAddress& other) const noexcept {
    return protocol == other.protocol && bytes == other.bytes;
}

bool IpAddress::operator!=(const IpAddress& other) const noexcept {
    return !(*this == other);
}

bool IpAddress::operator<(const IpAddress& other) const noexcept {
    if (protocol != other.protocol) {
        return protocol < other.protocol;
    }
    return bytes < other.bytes;
}

std::string IpAddress::to_string() const {
    if (protocol == NetworkProtocol::IPv4) {
        return std::to_string(bytes[0]) + "." +
               std::to_string(bytes[1]) + "." +
               std::to_string(bytes[2]) + "." +
               std::to_string(bytes[3]);
    }
    if (protocol == NetworkProtocol::IPv6) {
        std::ostringstream oss;
        for (std::size_t i = 0; i < 16; i += 2) {
            if (i > 0) {
                oss << ':';
            }
            const auto word = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(bytes[i]) << 8) | bytes[i + 1]);
            oss << std::hex << word;
        }
        return oss.str();
    }
    return "None";
}

std::optional<IpAddress> parse_ip_address(const std::string& text) noexcept {
    if (text.empty() || text.size() > 45) {
        return std::nullopt;
    }

    if (text.find('\0') != std::string::npos) {
        return std::nullopt;
    }

    std::uint8_t buf4[4];
    if (inet_pton(AF_INET, text.c_str(), buf4) == 1) {
        return IpAddress::from_ipv4(buf4);
    }

    std::uint8_t buf16[16];
    if (inet_pton(AF_INET6, text.c_str(), buf16) == 1) {
        return IpAddress::from_ipv6(buf16);
    }
    return std::nullopt;
}

}