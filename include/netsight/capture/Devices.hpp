#pragma once

#include <string>
#include <vector>

namespace netsight {

    struct NetworkInterface {
        std::string name;
        std::string description;
        std::string ipv4_address;
        bool is_loopback = false;
        bool is_up = true;
    };

    std::vector<NetworkInterface> list_interfaces(std::string& error_out);
}